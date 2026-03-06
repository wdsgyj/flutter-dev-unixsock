use once_cell::sync::Lazy;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{
    CertificateDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;
use std::os::raw::c_int;
use std::pin::Pin;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

const EVENT_CONNECT_OK: i32 = 1;
const EVENT_CONNECT_ERR: i32 = 2;
const EVENT_SOCKET_DATA: i32 = 3;
const EVENT_SOCKET_CLOSED: i32 = 4;
const EVENT_WRITE_OK: i32 = 5;
const EVENT_WRITE_ERR: i32 = 6;
const EVENT_SERVER_BOUND: i32 = 7;
const EVENT_SERVER_BIND_ERR: i32 = 8;
const EVENT_SERVER_ACCEPT: i32 = 9;
const EVENT_SERVER_CLOSED: i32 = 10;
const EVENT_SERVER_ERROR: i32 = 11;
const EVENT_SOCKET_ERROR: i32 = 12;
const EVENT_TLS_BAD_CERT: i32 = 100;
const EVENT_COMMAND_OK: i32 = 50;
const EVENT_COMMAND_ERR: i32 = 51;

type EventCallback = extern "C" fn(i64, i32, i64, i64, *const u8, usize);

#[derive(Default)]
struct SecurityContextState {
    trusted_certs_der: Vec<Vec<u8>>,
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_der: Option<PrivateKeyState>,
}

#[derive(Clone)]
enum PrivateKeyState {
    Pkcs8(Vec<u8>),
    Pkcs1(Vec<u8>),
}

struct SocketHandle {
    tx: mpsc::UnboundedSender<SocketCommand>,
}

enum SocketCommand {
    Write {
        request_id: i64,
        data: Vec<u8>,
    },
    Close {
        request_id: i64,
    },
    UpgradeTlsClient {
        request_id: i64,
        server_name: String,
        context_id: i64,
        allow_bad_cert_callback: bool,
    },
    UpgradeTlsServer {
        request_id: i64,
        context_id: i64,
        request_client_certificate: bool,
        require_client_certificate: bool,
    },
}

struct RuntimeState {
    callback: EventCallback,
    runtime: Runtime,
    next_socket_id: AtomicI64,
    next_server_id: AtomicI64,
    next_bad_cert_decision_id: AtomicI64,
    sockets: Mutex<HashMap<i64, SocketHandle>>,
    servers: Mutex<HashMap<i64, ServerEntry>>,
    bad_cert_decisions: Mutex<HashMap<i64, oneshot::Sender<bool>>>,
}

struct ServerEntry {
    join_handle: tokio::task::JoinHandle<()>,
    unix_path: Option<String>,
}

#[derive(Clone)]
struct TrackingServerCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    invalid_leaf_der: Arc<Mutex<Option<Vec<u8>>>>,
}

impl fmt::Debug for TrackingServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackingServerCertVerifier").finish()
    }
}

impl ServerCertVerifier for TrackingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(_) => {
                let mut guard = self
                    .invalid_leaf_der
                    .lock()
                    .expect("invalid cert mutex poisoned");
                *guard = Some(end_entity.as_ref().to_vec());
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

static RUNTIMES: Lazy<Mutex<HashMap<i64, Arc<RuntimeState>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CONTEXTS: Lazy<Mutex<HashMap<i64, Arc<Mutex<SecurityContextState>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_RUNTIME_ID: AtomicI64 = AtomicI64::new(1);
static NEXT_CONTEXT_ID: AtomicI64 = AtomicI64::new(1);

impl RuntimeState {
    fn emit(&self, request_id: i64, event: i32, arg0: i64, arg1: i64, data: Option<Vec<u8>>) {
        match data {
            Some(mut bytes) => {
                let len = bytes.len();
                let ptr = bytes.as_mut_ptr();
                std::mem::forget(bytes);
                (self.callback)(request_id, event, arg0, arg1, ptr as *const u8, len);
            }
            None => {
                (self.callback)(request_id, event, arg0, arg1, ptr::null(), 0);
            }
        }
    }

    fn emit_error(&self, request_id: i64, event: i32, arg0: i64, message: String) {
        self.emit(request_id, event, arg0, 0, Some(message.into_bytes()));
    }

    fn next_socket_id(&self) -> i64 {
        self.next_socket_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_server_id(&self) -> i64 {
        self.next_server_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_bad_cert_decision_id(&self) -> i64 {
        self.next_bad_cert_decision_id
            .fetch_add(1, Ordering::Relaxed)
    }

    fn insert_socket(&self, socket_id: i64, socket: SocketHandle) {
        self.sockets
            .lock()
            .expect("sockets mutex poisoned")
            .insert(socket_id, socket);
    }

    fn with_socket_sender<F>(&self, socket_id: i64, f: F) -> bool
    where
        F: FnOnce(&mpsc::UnboundedSender<SocketCommand>) -> bool,
    {
        let sockets = self.sockets.lock().expect("sockets mutex poisoned");
        let Some(handle) = sockets.get(&socket_id) else {
            return false;
        };
        f(&handle.tx)
    }

    fn remove_socket(&self, socket_id: i64) {
        self.sockets
            .lock()
            .expect("sockets mutex poisoned")
            .remove(&socket_id);
    }

    fn insert_server(&self, server_id: i64, entry: ServerEntry) {
        self.servers
            .lock()
            .expect("servers mutex poisoned")
            .insert(server_id, entry);
    }

    fn take_server(&self, server_id: i64) -> Option<ServerEntry> {
        self.servers
            .lock()
            .expect("servers mutex poisoned")
            .remove(&server_id)
    }

    fn insert_bad_cert_sender(&self, decision_id: i64, sender: oneshot::Sender<bool>) {
        self.bad_cert_decisions
            .lock()
            .expect("bad cert decisions mutex poisoned")
            .insert(decision_id, sender);
    }

    fn take_bad_cert_sender(&self, decision_id: i64) -> Option<oneshot::Sender<bool>> {
        self.bad_cert_decisions
            .lock()
            .expect("bad cert decisions mutex poisoned")
            .remove(&decision_id)
    }
}

fn parse_c_string(input: *const c_char) -> Result<String, String> {
    if input.is_null() {
        return Err("argument cannot be null".to_string());
    }

    let cstr = unsafe { CStr::from_ptr(input) };
    cstr.to_str()
        .map(|s| s.to_owned())
        .map_err(|err| format!("invalid UTF-8 string: {err}"))
}

fn parse_timeout(timeout_ms: i64) -> Option<Duration> {
    if timeout_ms <= 0 {
        None
    } else {
        Some(Duration::from_millis(timeout_ms as u64))
    }
}

fn get_runtime(runtime_id: i64) -> Option<Arc<RuntimeState>> {
    RUNTIMES
        .lock()
        .expect("runtime map mutex poisoned")
        .get(&runtime_id)
        .cloned()
}

fn parse_certificate_chain(pem: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut cursor = Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse certificate chain failed: {err}"))?;

    if certs.is_empty() {
        return Err("no certificates found in PEM".to_string());
    }

    Ok(certs
        .into_iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect())
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyState, String> {
    let mut cursor = Cursor::new(pem);
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse PKCS8 private key failed: {err}"))?;

    if let Some(key) = pkcs8_keys.into_iter().next() {
        return Ok(PrivateKeyState::Pkcs8(key.secret_pkcs8_der().to_vec()));
    }

    cursor.set_position(0);
    let rsa_keys = rustls_pemfile::rsa_private_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse RSA private key failed: {err}"))?;
    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(PrivateKeyState::Pkcs1(key.secret_pkcs1_der().to_vec()));
    }

    Err("no private key found in PEM".to_string())
}

fn build_server_name(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    ServerName::try_from(host.to_owned()).map_err(|_| format!("invalid server name: {host}"))
}

fn private_key_der_from_state(
    key_state: PrivateKeyState,
) -> rustls::pki_types::PrivateKeyDer<'static> {
    match key_state {
        PrivateKeyState::Pkcs8(bytes) => {
            rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes))
        }
        PrivateKeyState::Pkcs1(bytes) => {
            rustls::pki_types::PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(bytes))
        }
    }
}

fn build_client_tls_config(
    context_id: i64,
) -> Result<(Arc<ClientConfig>, Arc<Mutex<Option<Vec<u8>>>>), String> {
    let mut root_store = RootCertStore::empty();
    let mut client_auth: Option<(
        Vec<CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> = None;

    if context_id > 0 {
        let context = CONTEXTS
            .lock()
            .expect("context map mutex poisoned")
            .get(&context_id)
            .cloned()
            .ok_or_else(|| format!("security context not found: {context_id}"))?;
        let state = context.lock().expect("context mutex poisoned");

        if state.trusted_certs_der.is_empty() {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for cert_der in &state.trusted_certs_der {
                root_store
                    .add(CertificateDer::from(cert_der.clone()))
                    .map_err(|err| format!("invalid trusted certificate: {err}"))?;
            }
        }

        if !state.certificate_chain_der.is_empty() || state.private_key_der.is_some() {
            if state.certificate_chain_der.is_empty() {
                return Err(
                    "security context missing certificate chain for client auth".to_string()
                );
            }
            let key_state = state.private_key_der.clone().ok_or_else(|| {
                "security context missing private key for client auth".to_string()
            })?;

            let cert_chain: Vec<CertificateDer<'static>> = state
                .certificate_chain_der
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect();
            client_auth = Some((cert_chain, private_key_der_from_state(key_state)));
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let inner_verifier = WebPkiServerVerifier::builder(Arc::new(root_store.clone()))
        .build()
        .map_err(|err| format!("build webpki verifier failed: {err}"))?;

    let invalid_leaf_der: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let tracking_verifier: Arc<dyn ServerCertVerifier> = Arc::new(TrackingServerCertVerifier {
        inner: inner_verifier,
        invalid_leaf_der: invalid_leaf_der.clone(),
    });

    let mut config = if let Some((cert_chain, private_key)) = client_auth {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|err| format!("build client auth config failed: {err}"))?
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    config
        .dangerous()
        .set_certificate_verifier(tracking_verifier);

    Ok((Arc::new(config), invalid_leaf_der))
}

fn build_server_tls_config(
    context_id: i64,
    request_client_certificate: bool,
    require_client_certificate: bool,
) -> Result<Arc<ServerConfig>, String> {
    if context_id <= 0 {
        return Err("security context is required for server TLS".to_string());
    }

    let context = CONTEXTS
        .lock()
        .expect("context map mutex poisoned")
        .get(&context_id)
        .cloned()
        .ok_or_else(|| format!("security context not found: {context_id}"))?;
    let state = context.lock().expect("context mutex poisoned");

    if state.certificate_chain_der.is_empty() {
        return Err("security context missing certificate chain".to_string());
    }
    let key_state = state
        .private_key_der
        .clone()
        .ok_or_else(|| "security context missing private key".to_string())?;

    let cert_chain: Vec<CertificateDer<'static>> = state
        .certificate_chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();

    let key = private_key_der_from_state(key_state);

    let builder = if request_client_certificate || require_client_certificate {
        let mut roots = RootCertStore::empty();
        for cert_der in &state.trusted_certs_der {
            roots
                .add(CertificateDer::from(cert_der.clone()))
                .map_err(|err| format!("invalid trusted certificate: {err}"))?;
        }
        if roots.is_empty() {
            return Err(
                "request/require client certificate requires trusted client CA certs".to_string(),
            );
        }

        let verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
        let verifier = if require_client_certificate {
            verifier_builder
                .build()
                .map_err(|err| format!("build client verifier failed: {err}"))?
        } else {
            verifier_builder
                .allow_unauthenticated()
                .build()
                .map_err(|err| format!("build optional client verifier failed: {err}"))?
        };
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };

    let config = builder
        .with_single_cert(cert_chain, key)
        .map_err(|err| format!("build server tls config failed: {err}"))?;

    Ok(Arc::new(config))
}

enum ManagedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Plain(S),
    Tls(TlsStream<S>),
}

impl<S> AsyncRead for ManagedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for ManagedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

fn register_socket_stream<S>(runtime: Arc<RuntimeState>, stream: S) -> i64
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let socket_id = runtime.next_socket_id();
    let (mut reader, mut writer) = tokio::io::split(ManagedStream::Plain(stream));
    let (tx, mut rx) = mpsc::unbounded_channel::<SocketCommand>();
    runtime.insert_socket(socket_id, SocketHandle { tx });

    let runtime_for_task = runtime.clone();
    runtime.runtime.spawn(async move {
        let mut buffer = vec![0u8; 8192];
        let mut closed = false;

        while !closed {
            tokio::select! {
                maybe_command = rx.recv() => {
                    match maybe_command {
                        Some(SocketCommand::Write { request_id, data }) => {
                            match writer.write_all(&data).await {
                                Ok(()) => runtime_for_task.emit(
                                    request_id,
                                    EVENT_WRITE_OK,
                                    socket_id,
                                    data.len() as i64,
                                    None,
                                ),
                                Err(err) => {
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_WRITE_ERR,
                                        socket_id,
                                        format!("write failed: {err}"),
                                    );
                                    runtime_for_task.emit_error(
                                        0,
                                        EVENT_SOCKET_ERROR,
                                        socket_id,
                                        format!("write failed: {err}"),
                                    );
                                    closed = true;
                                }
                            }
                        }
                        Some(SocketCommand::Close { request_id }) => {
                            match writer.shutdown().await {
                                Ok(()) => runtime_for_task.emit(
                                    request_id,
                                    EVENT_COMMAND_OK,
                                    socket_id,
                                    0,
                                    None,
                                ),
                                Err(err) => runtime_for_task.emit_error(
                                    request_id,
                                    EVENT_COMMAND_ERR,
                                    socket_id,
                                    format!("shutdown failed: {err}"),
                                ),
                            }
                            closed = true;
                        }
                        Some(SocketCommand::UpgradeTlsClient {
                            request_id,
                            server_name,
                            context_id,
                            allow_bad_cert_callback,
                        }) => {
                            let managed_stream = reader.unsplit(writer);
                            let plain_stream = match managed_stream {
                                ManagedStream::Plain(stream) => stream,
                                ManagedStream::Tls(tls_stream) => {
                                    let (new_reader, new_writer) =
                                        tokio::io::split(ManagedStream::Tls(tls_stream));
                                    reader = new_reader;
                                    writer = new_writer;
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        "socket is already secure".to_string(),
                                    );
                                    continue;
                                }
                            };

                            let server_name = match build_server_name(server_name.as_str()) {
                                Ok(name) => name,
                                Err(err) => {
                                    let (new_reader, new_writer) =
                                        tokio::io::split(ManagedStream::Plain(plain_stream));
                                    reader = new_reader;
                                    writer = new_writer;
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        err,
                                    );
                                    continue;
                                }
                            };

                            let (config, invalid_leaf_der) = match build_client_tls_config(context_id) {
                                Ok(config) => config,
                                Err(err) => {
                                    let (new_reader, new_writer) =
                                        tokio::io::split(ManagedStream::Plain(plain_stream));
                                    reader = new_reader;
                                    writer = new_writer;
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        err,
                                    );
                                    continue;
                                }
                            };

                            let connector = TlsConnector::from(config);
                            let tls_stream = match connector.connect(server_name, plain_stream).await {
                                Ok(stream) => stream,
                                Err(err) => {
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        format!("tls handshake failed: {err}"),
                                    );
                                    runtime_for_task.emit_error(
                                        0,
                                        EVENT_SOCKET_ERROR,
                                        socket_id,
                                        format!("tls handshake failed: {err}"),
                                    );
                                    break;
                                }
                            };

                            if let Err(err) = resolve_bad_certificate(
                                runtime_for_task.clone(),
                                request_id,
                                invalid_leaf_der,
                                allow_bad_cert_callback,
                            )
                            .await
                            {
                                runtime_for_task.emit_error(
                                    request_id,
                                    EVENT_COMMAND_ERR,
                                    socket_id,
                                    err.clone(),
                                );
                                runtime_for_task.emit_error(
                                    0,
                                    EVENT_SOCKET_ERROR,
                                    socket_id,
                                    err,
                                );
                                break;
                            }

                            let (new_reader, new_writer) =
                                tokio::io::split(ManagedStream::Tls(tls_stream.into()));
                            reader = new_reader;
                            writer = new_writer;
                            runtime_for_task.emit(
                                request_id,
                                EVENT_COMMAND_OK,
                                socket_id,
                                0,
                                None,
                            );
                        }
                        Some(SocketCommand::UpgradeTlsServer {
                            request_id,
                            context_id,
                            request_client_certificate,
                            require_client_certificate,
                        }) => {
                            let managed_stream = reader.unsplit(writer);
                            let plain_stream = match managed_stream {
                                ManagedStream::Plain(stream) => stream,
                                ManagedStream::Tls(tls_stream) => {
                                    let (new_reader, new_writer) =
                                        tokio::io::split(ManagedStream::Tls(tls_stream));
                                    reader = new_reader;
                                    writer = new_writer;
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        "socket is already secure".to_string(),
                                    );
                                    continue;
                                }
                            };

                            let config = match build_server_tls_config(
                                context_id,
                                request_client_certificate,
                                require_client_certificate,
                            ) {
                                Ok(config) => config,
                                Err(err) => {
                                    let (new_reader, new_writer) =
                                        tokio::io::split(ManagedStream::Plain(plain_stream));
                                    reader = new_reader;
                                    writer = new_writer;
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        err,
                                    );
                                    continue;
                                }
                            };

                            let acceptor = TlsAcceptor::from(config);
                            let tls_stream = match acceptor.accept(plain_stream).await {
                                Ok(stream) => stream,
                                Err(err) => {
                                    runtime_for_task.emit_error(
                                        request_id,
                                        EVENT_COMMAND_ERR,
                                        socket_id,
                                        format!("tls server handshake failed: {err}"),
                                    );
                                    runtime_for_task.emit_error(
                                        0,
                                        EVENT_SOCKET_ERROR,
                                        socket_id,
                                        format!("tls server handshake failed: {err}"),
                                    );
                                    break;
                                }
                            };

                            let (new_reader, new_writer) =
                                tokio::io::split(ManagedStream::Tls(tls_stream.into()));
                            reader = new_reader;
                            writer = new_writer;
                            runtime_for_task.emit(
                                request_id,
                                EVENT_COMMAND_OK,
                                socket_id,
                                0,
                                None,
                            );
                        }
                        None => {
                            closed = true;
                        }
                    }
                }
                read_result = reader.read(&mut buffer) => {
                    match read_result {
                        Ok(0) => {
                            closed = true;
                        }
                        Ok(read) => {
                            runtime_for_task.emit(
                                0,
                                EVENT_SOCKET_DATA,
                                socket_id,
                                read as i64,
                                Some(buffer[..read].to_vec()),
                            );
                        }
                        Err(err) => {
                            runtime_for_task.emit_error(
                                0,
                                EVENT_SOCKET_ERROR,
                                socket_id,
                                format!("read failed: {err}"),
                            );
                            closed = true;
                        }
                    }
                }
            }
        }

        runtime_for_task.remove_socket(socket_id);
        runtime_for_task.emit(0, EVENT_SOCKET_CLOSED, socket_id, 0, None);
    });

    socket_id
}

async fn resolve_bad_certificate(
    runtime: Arc<RuntimeState>,
    request_id: i64,
    invalid_leaf_der: Arc<Mutex<Option<Vec<u8>>>>,
    allow_callback: bool,
) -> Result<(), String> {
    let bad_cert = {
        let mut guard = invalid_leaf_der
            .lock()
            .expect("invalid cert state mutex poisoned");
        guard.take()
    };

    let Some(cert_der) = bad_cert else {
        return Ok(());
    };

    if !allow_callback {
        return Err("certificate verification failed".to_string());
    }

    let decision_id = runtime.next_bad_cert_decision_id();
    let (tx, rx) = oneshot::channel::<bool>();
    runtime.insert_bad_cert_sender(decision_id, tx);
    runtime.emit(
        request_id,
        EVENT_TLS_BAD_CERT,
        decision_id,
        cert_der.len() as i64,
        Some(cert_der),
    );

    let accepted = match tokio::time::timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(result)) => result,
        _ => false,
    };

    if !accepted {
        let _ = runtime.take_bad_cert_sender(decision_id);
        return Err("certificate rejected by onBadCertificate".to_string());
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn unixsock_rs_buffer_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

#[no_mangle]
pub extern "C" fn unixsock_rs_runtime_new(callback: Option<EventCallback>) -> i64 {
    let Some(callback) = callback else {
        return 0;
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 0,
    };

    let state = Arc::new(RuntimeState {
        callback,
        runtime,
        next_socket_id: AtomicI64::new(1),
        next_server_id: AtomicI64::new(1),
        next_bad_cert_decision_id: AtomicI64::new(1),
        sockets: Mutex::new(HashMap::new()),
        servers: Mutex::new(HashMap::new()),
        bad_cert_decisions: Mutex::new(HashMap::new()),
    });

    let runtime_id = NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
    RUNTIMES
        .lock()
        .expect("runtime map mutex poisoned")
        .insert(runtime_id, state);
    runtime_id
}

#[no_mangle]
pub extern "C" fn unixsock_rs_runtime_free(runtime_id: i64) -> c_int {
    let Some(state) = RUNTIMES
        .lock()
        .expect("runtime map mutex poisoned")
        .remove(&runtime_id)
    else {
        return -1;
    };

    {
        let mut servers = state.servers.lock().expect("servers mutex poisoned");
        for (_, entry) in servers.drain() {
            entry.join_handle.abort();
            if let Some(path) = entry.unix_path {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    state
        .sockets
        .lock()
        .expect("sockets mutex poisoned")
        .clear();
    state
        .bad_cert_decisions
        .lock()
        .expect("bad cert decisions mutex poisoned")
        .clear();
    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_security_context_new() -> i64 {
    let context_id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
    CONTEXTS.lock().expect("context map mutex poisoned").insert(
        context_id,
        Arc::new(Mutex::new(SecurityContextState::default())),
    );
    context_id
}

#[no_mangle]
pub extern "C" fn unixsock_rs_security_context_free(context_id: i64) -> c_int {
    if CONTEXTS
        .lock()
        .expect("context map mutex poisoned")
        .remove(&context_id)
        .is_some()
    {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn unixsock_rs_security_context_set_trusted_certs_pem(
    context_id: i64,
    pem: *const u8,
    len: usize,
) -> c_int {
    if pem.is_null() || len == 0 {
        return -1;
    }

    let Some(context) = CONTEXTS
        .lock()
        .expect("context map mutex poisoned")
        .get(&context_id)
        .cloned()
    else {
        return -1;
    };

    let bytes = unsafe { slice::from_raw_parts(pem, len) };
    let certs = match parse_certificate_chain(bytes) {
        Ok(certs) => certs,
        Err(_) => return -1,
    };

    context
        .lock()
        .expect("context mutex poisoned")
        .trusted_certs_der = certs;
    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_security_context_use_certificate_chain_pem(
    context_id: i64,
    pem: *const u8,
    len: usize,
) -> c_int {
    if pem.is_null() || len == 0 {
        return -1;
    }

    let Some(context) = CONTEXTS
        .lock()
        .expect("context map mutex poisoned")
        .get(&context_id)
        .cloned()
    else {
        return -1;
    };

    let bytes = unsafe { slice::from_raw_parts(pem, len) };
    let certs = match parse_certificate_chain(bytes) {
        Ok(certs) => certs,
        Err(_) => return -1,
    };

    context
        .lock()
        .expect("context mutex poisoned")
        .certificate_chain_der = certs;
    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_security_context_use_private_key_pem(
    context_id: i64,
    pem: *const u8,
    len: usize,
) -> c_int {
    if pem.is_null() || len == 0 {
        return -1;
    }

    let Some(context) = CONTEXTS
        .lock()
        .expect("context map mutex poisoned")
        .get(&context_id)
        .cloned()
    else {
        return -1;
    };

    let bytes = unsafe { slice::from_raw_parts(pem, len) };
    let key = match parse_private_key(bytes) {
        Ok(key) => key,
        Err(_) => return -1,
    };

    context
        .lock()
        .expect("context mutex poisoned")
        .private_key_der = Some(key);
    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tcp_connect(
    runtime_id: i64,
    request_id: i64,
    host: *const c_char,
    port: u16,
    timeout_ms: i64,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let host = match parse_c_string(host) {
        Ok(host) => host,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    let connect_timeout = parse_timeout(timeout_ms);
    let runtime_for_task = runtime.clone();
    runtime.runtime.spawn(async move {
        let result = match connect_timeout {
            Some(timeout_duration) => {
                match tokio::time::timeout(
                    timeout_duration,
                    TcpStream::connect((host.as_str(), port)),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        runtime_for_task.emit_error(
                            request_id,
                            EVENT_CONNECT_ERR,
                            0,
                            format!("tcp connect timeout after {timeout_ms}ms"),
                        );
                        return;
                    }
                }
            }
            None => TcpStream::connect((host.as_str(), port)).await,
        };

        match result {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let socket_id = register_socket_stream(runtime_for_task.clone(), stream);
                runtime_for_task.emit(request_id, EVENT_CONNECT_OK, socket_id, 0, None);
            }
            Err(err) => {
                runtime_for_task.emit_error(
                    request_id,
                    EVENT_CONNECT_ERR,
                    0,
                    format!("tcp connect failed: {err}"),
                );
            }
        }
    });

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_unix_connect(
    runtime_id: i64,
    request_id: i64,
    path: *const c_char,
    timeout_ms: i64,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let path = match parse_c_string(path) {
        Ok(path) => path,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    #[cfg(not(unix))]
    {
        let _ = timeout_ms;
        runtime.emit_error(
            request_id,
            EVENT_CONNECT_ERR,
            0,
            "unix sockets are unsupported on this target".to_string(),
        );
        return -1;
    }

    #[cfg(unix)]
    {
        let connect_timeout = parse_timeout(timeout_ms);
        let runtime_for_task = runtime.clone();
        runtime.runtime.spawn(async move {
            let result = match connect_timeout {
                Some(timeout_duration) => {
                    match tokio::time::timeout(timeout_duration, UnixStream::connect(path.as_str()))
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            runtime_for_task.emit_error(
                                request_id,
                                EVENT_CONNECT_ERR,
                                0,
                                format!("unix connect timeout after {timeout_ms}ms"),
                            );
                            return;
                        }
                    }
                }
                None => UnixStream::connect(path.as_str()).await,
            };

            match result {
                Ok(stream) => {
                    let socket_id = register_socket_stream(runtime_for_task.clone(), stream);
                    runtime_for_task.emit(request_id, EVENT_CONNECT_OK, socket_id, 0, None);
                }
                Err(err) => {
                    runtime_for_task.emit_error(
                        request_id,
                        EVENT_CONNECT_ERR,
                        0,
                        format!("unix connect failed: {err}"),
                    );
                }
            }
        });

        0
    }
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tls_connect_tcp(
    runtime_id: i64,
    request_id: i64,
    host: *const c_char,
    port: u16,
    context_id: i64,
    timeout_ms: i64,
    allow_bad_cert_callback: c_int,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let host = match parse_c_string(host) {
        Ok(host) => host,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    let server_name = match build_server_name(host.as_str()) {
        Ok(name) => name,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    let (config, invalid_leaf_der) = match build_client_tls_config(context_id) {
        Ok(config) => config,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    let timeout = parse_timeout(timeout_ms);
    let runtime_for_task = runtime.clone();
    runtime.runtime.spawn(async move {
        let stream_result = match timeout {
            Some(duration) => {
                match tokio::time::timeout(duration, TcpStream::connect((host.as_str(), port)))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        runtime_for_task.emit_error(
                            request_id,
                            EVENT_CONNECT_ERR,
                            0,
                            format!("tcp connect timeout after {timeout_ms}ms"),
                        );
                        return;
                    }
                }
            }
            None => TcpStream::connect((host.as_str(), port)).await,
        };

        let stream = match stream_result {
            Ok(stream) => stream,
            Err(err) => {
                runtime_for_task.emit_error(
                    request_id,
                    EVENT_CONNECT_ERR,
                    0,
                    format!("tcp connect failed: {err}"),
                );
                return;
            }
        };

        let _ = stream.set_nodelay(true);
        let connector = TlsConnector::from(config);
        let tls_stream_result = match timeout {
            Some(duration) => {
                match tokio::time::timeout(duration, connector.connect(server_name, stream)).await {
                    Ok(result) => result,
                    Err(_) => {
                        runtime_for_task.emit_error(
                            request_id,
                            EVENT_CONNECT_ERR,
                            0,
                            format!("tls handshake timeout after {timeout_ms}ms"),
                        );
                        return;
                    }
                }
            }
            None => connector.connect(server_name, stream).await,
        };

        let tls_stream = match tls_stream_result {
            Ok(stream) => stream,
            Err(err) => {
                runtime_for_task.emit_error(
                    request_id,
                    EVENT_CONNECT_ERR,
                    0,
                    format!("tls handshake failed: {err}"),
                );
                return;
            }
        };

        if let Err(err) = resolve_bad_certificate(
            runtime_for_task.clone(),
            request_id,
            invalid_leaf_der,
            allow_bad_cert_callback != 0,
        )
        .await
        {
            runtime_for_task.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return;
        }

        let socket_id = register_socket_stream(runtime_for_task.clone(), tls_stream);
        runtime_for_task.emit(request_id, EVENT_CONNECT_OK, socket_id, 0, None);
    });

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tls_connect_unix(
    runtime_id: i64,
    request_id: i64,
    path: *const c_char,
    server_name: *const c_char,
    context_id: i64,
    timeout_ms: i64,
    allow_bad_cert_callback: c_int,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let path = match parse_c_string(path) {
        Ok(path) => path,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    let server_name =
        match parse_c_string(server_name).and_then(|name| build_server_name(name.as_str())) {
            Ok(name) => name,
            Err(err) => {
                runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
                return -1;
            }
        };

    let (config, invalid_leaf_der) = match build_client_tls_config(context_id) {
        Ok(config) => config,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
            return -1;
        }
    };

    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = timeout_ms;
        let _ = config;
        let _ = invalid_leaf_der;
        let _ = server_name;
        let _ = allow_bad_cert_callback;
        runtime.emit_error(
            request_id,
            EVENT_CONNECT_ERR,
            0,
            "unix sockets are unsupported on this target".to_string(),
        );
        return -1;
    }

    #[cfg(unix)]
    {
        let timeout = parse_timeout(timeout_ms);
        let runtime_for_task = runtime.clone();
        runtime.runtime.spawn(async move {
            let stream_result = match timeout {
                Some(duration) => {
                    match tokio::time::timeout(duration, UnixStream::connect(path.as_str())).await {
                        Ok(result) => result,
                        Err(_) => {
                            runtime_for_task.emit_error(
                                request_id,
                                EVENT_CONNECT_ERR,
                                0,
                                format!("unix connect timeout after {timeout_ms}ms"),
                            );
                            return;
                        }
                    }
                }
                None => UnixStream::connect(path.as_str()).await,
            };

            let stream = match stream_result {
                Ok(stream) => stream,
                Err(err) => {
                    runtime_for_task.emit_error(
                        request_id,
                        EVENT_CONNECT_ERR,
                        0,
                        format!("unix connect failed: {err}"),
                    );
                    return;
                }
            };

            let connector = TlsConnector::from(config);
            let tls_stream_result = match timeout {
                Some(duration) => {
                    match tokio::time::timeout(duration, connector.connect(server_name, stream))
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            runtime_for_task.emit_error(
                                request_id,
                                EVENT_CONNECT_ERR,
                                0,
                                format!("tls handshake timeout after {timeout_ms}ms"),
                            );
                            return;
                        }
                    }
                }
                None => connector.connect(server_name, stream).await,
            };

            let tls_stream = match tls_stream_result {
                Ok(stream) => stream,
                Err(err) => {
                    runtime_for_task.emit_error(
                        request_id,
                        EVENT_CONNECT_ERR,
                        0,
                        format!("tls handshake failed: {err}"),
                    );
                    return;
                }
            };

            if let Err(err) = resolve_bad_certificate(
                runtime_for_task.clone(),
                request_id,
                invalid_leaf_der,
                allow_bad_cert_callback != 0,
            )
            .await
            {
                runtime_for_task.emit_error(request_id, EVENT_CONNECT_ERR, 0, err);
                return;
            }

            let socket_id = register_socket_stream(runtime_for_task.clone(), tls_stream);
            runtime_for_task.emit(request_id, EVENT_CONNECT_OK, socket_id, 0, None);
        });

        0
    }
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tls_bad_cert_decision(
    runtime_id: i64,
    decision_id: i64,
    accept: c_int,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let Some(sender) = runtime.take_bad_cert_sender(decision_id) else {
        return -1;
    };

    if sender.send(accept != 0).is_err() {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tls_secure_socket(
    runtime_id: i64,
    request_id: i64,
    socket_id: i64,
    server_name: *const c_char,
    context_id: i64,
    allow_bad_cert_callback: c_int,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let server_name = match parse_c_string(server_name) {
        Ok(name) => name,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_COMMAND_ERR, socket_id, err);
            return -1;
        }
    };

    let sent = runtime.with_socket_sender(socket_id, |tx| {
        tx.send(SocketCommand::UpgradeTlsClient {
            request_id,
            server_name,
            context_id,
            allow_bad_cert_callback: allow_bad_cert_callback != 0,
        })
        .is_ok()
    });
    if !sent {
        runtime.emit_error(
            request_id,
            EVENT_COMMAND_ERR,
            socket_id,
            "socket not found".to_string(),
        );
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tls_secure_server_socket(
    runtime_id: i64,
    request_id: i64,
    socket_id: i64,
    context_id: i64,
    request_client_certificate: c_int,
    require_client_certificate: c_int,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let sent = runtime.with_socket_sender(socket_id, |tx| {
        tx.send(SocketCommand::UpgradeTlsServer {
            request_id,
            context_id,
            request_client_certificate: request_client_certificate != 0,
            require_client_certificate: require_client_certificate != 0,
        })
        .is_ok()
    });
    if !sent {
        runtime.emit_error(
            request_id,
            EVENT_COMMAND_ERR,
            socket_id,
            "socket not found".to_string(),
        );
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_socket_write(
    runtime_id: i64,
    request_id: i64,
    socket_id: i64,
    data: *const u8,
    len: usize,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    if len == 0 {
        runtime.emit(request_id, EVENT_WRITE_OK, socket_id, 0, None);
        return 0;
    }
    if data.is_null() {
        runtime.emit_error(
            request_id,
            EVENT_WRITE_ERR,
            socket_id,
            "write data cannot be null".to_string(),
        );
        return -1;
    }

    let bytes = unsafe { slice::from_raw_parts(data, len) }.to_vec();
    let sent = runtime.with_socket_sender(socket_id, |tx| {
        tx.send(SocketCommand::Write {
            request_id,
            data: bytes,
        })
        .is_ok()
    });
    if !sent {
        runtime.emit_error(
            request_id,
            EVENT_WRITE_ERR,
            socket_id,
            "socket not found".to_string(),
        );
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_socket_close(
    runtime_id: i64,
    request_id: i64,
    socket_id: i64,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let sent = runtime.with_socket_sender(socket_id, |tx| {
        tx.send(SocketCommand::Close { request_id }).is_ok()
    });
    if !sent {
        runtime.emit_error(
            request_id,
            EVENT_COMMAND_ERR,
            socket_id,
            "socket not found".to_string(),
        );
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_tcp_bind(
    runtime_id: i64,
    request_id: i64,
    host: *const c_char,
    port: u16,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let host = match parse_c_string(host) {
        Ok(host) => host,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_SERVER_BIND_ERR, 0, err);
            return -1;
        }
    };

    let runtime_for_task = runtime.clone();
    runtime.runtime.spawn(async move {
        match TcpListener::bind((host.as_str(), port)).await {
            Ok(listener) => {
                let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                let server_id = runtime_for_task.next_server_id();
                let runtime_for_accept = runtime_for_task.clone();
                let join_handle = tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                let socket_id =
                                    register_socket_stream(runtime_for_accept.clone(), stream);
                                runtime_for_accept.emit(
                                    0,
                                    EVENT_SERVER_ACCEPT,
                                    server_id,
                                    socket_id,
                                    None,
                                );
                            }
                            Err(err) => {
                                runtime_for_accept.emit_error(
                                    0,
                                    EVENT_SERVER_ERROR,
                                    server_id,
                                    format!("tcp accept failed: {err}"),
                                );
                                runtime_for_accept.emit(0, EVENT_SERVER_CLOSED, server_id, 0, None);
                                break;
                            }
                        }
                    }
                });

                runtime_for_task.insert_server(
                    server_id,
                    ServerEntry {
                        join_handle,
                        unix_path: None,
                    },
                );
                runtime_for_task.emit(
                    request_id,
                    EVENT_SERVER_BOUND,
                    server_id,
                    bound_port as i64,
                    None,
                );
            }
            Err(err) => runtime_for_task.emit_error(
                request_id,
                EVENT_SERVER_BIND_ERR,
                0,
                format!("tcp bind failed: {err}"),
            ),
        }
    });

    0
}

#[no_mangle]
pub extern "C" fn unixsock_rs_unix_bind(
    runtime_id: i64,
    request_id: i64,
    path: *const c_char,
    remove_existing: c_int,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let path = match parse_c_string(path) {
        Ok(path) => path,
        Err(err) => {
            runtime.emit_error(request_id, EVENT_SERVER_BIND_ERR, 0, err);
            return -1;
        }
    };

    #[cfg(not(unix))]
    {
        let _ = remove_existing;
        runtime.emit_error(
            request_id,
            EVENT_SERVER_BIND_ERR,
            0,
            "unix sockets are unsupported on this target".to_string(),
        );
        return -1;
    }

    #[cfg(unix)]
    {
        let runtime_for_task = runtime.clone();
        runtime.runtime.spawn(async move {
            if remove_existing != 0 {
                let _ = std::fs::remove_file(path.as_str());
            }

            match UnixListener::bind(path.as_str()) {
                Ok(listener) => {
                    let server_id = runtime_for_task.next_server_id();
                    let unix_path = path.clone();
                    let runtime_for_accept = runtime_for_task.clone();
                    let join_handle = tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((stream, _)) => {
                                    let socket_id =
                                        register_socket_stream(runtime_for_accept.clone(), stream);
                                    runtime_for_accept.emit(
                                        0,
                                        EVENT_SERVER_ACCEPT,
                                        server_id,
                                        socket_id,
                                        None,
                                    );
                                }
                                Err(err) => {
                                    runtime_for_accept.emit_error(
                                        0,
                                        EVENT_SERVER_ERROR,
                                        server_id,
                                        format!("unix accept failed: {err}"),
                                    );
                                    runtime_for_accept.emit(
                                        0,
                                        EVENT_SERVER_CLOSED,
                                        server_id,
                                        0,
                                        None,
                                    );
                                    break;
                                }
                            }
                        }
                    });

                    runtime_for_task.insert_server(
                        server_id,
                        ServerEntry {
                            join_handle,
                            unix_path: Some(unix_path),
                        },
                    );
                    runtime_for_task.emit(request_id, EVENT_SERVER_BOUND, server_id, 0, None);
                }
                Err(err) => runtime_for_task.emit_error(
                    request_id,
                    EVENT_SERVER_BIND_ERR,
                    0,
                    format!("unix bind failed: {err}"),
                ),
            }
        });

        0
    }
}

#[no_mangle]
pub extern "C" fn unixsock_rs_server_close(
    runtime_id: i64,
    request_id: i64,
    server_id: i64,
) -> c_int {
    let Some(runtime) = get_runtime(runtime_id) else {
        return -1;
    };

    let Some(entry) = runtime.take_server(server_id) else {
        runtime.emit_error(
            request_id,
            EVENT_COMMAND_ERR,
            server_id,
            "server not found".to_string(),
        );
        return -1;
    };

    entry.join_handle.abort();
    if let Some(path) = entry.unix_path {
        let _ = std::fs::remove_file(path);
    }

    runtime.emit(request_id, EVENT_COMMAND_OK, server_id, 0, None);
    runtime.emit(0, EVENT_SERVER_CLOSED, server_id, 0, None);
    0
}

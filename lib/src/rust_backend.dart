import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

const int _eventConnectOk = 1;
const int _eventSocketData = 3;
const int _eventSocketClosed = 4;
const int _eventWriteOk = 5;
const int _eventServerBound = 7;
const int _eventServerAccept = 9;
const int _eventServerClosed = 10;
const int _eventServerError = 11;
const int _eventSocketError = 12;
const int _eventTlsBadCert = 100;
const int _eventCommandOk = 50;

typedef _EventNative = Void Function(
  Int64 requestId,
  Int32 event,
  Int64 arg0,
  Int64 arg1,
  Pointer<Uint8> data,
  IntPtr len,
);

typedef _RuntimeNewNative = Int64 Function(
  Pointer<NativeFunction<_EventNative>> callback,
);
typedef _RuntimeNewDart = int Function(
  Pointer<NativeFunction<_EventNative>> callback,
);

typedef _RuntimeFreeNative = Int32 Function(Int64 runtimeId);
typedef _RuntimeFreeDart = int Function(int runtimeId);

typedef _BufferFreeNative = Void Function(Pointer<Uint8> ptr, IntPtr len);
typedef _BufferFreeDart = void Function(Pointer<Uint8> ptr, int len);

typedef _TcpConnectNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Pointer<Int8> host,
  Uint16 port,
  Int64 timeoutMs,
);
typedef _TcpConnectDart = int Function(
  int runtimeId,
  int requestId,
  Pointer<Int8> host,
  int port,
  int timeoutMs,
);

typedef _UnixConnectNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Pointer<Int8> path,
  Int64 timeoutMs,
);
typedef _UnixConnectDart = int Function(
  int runtimeId,
  int requestId,
  Pointer<Int8> path,
  int timeoutMs,
);

typedef _TlsConnectTcpNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Pointer<Int8> host,
  Uint16 port,
  Int64 contextId,
  Int64 timeoutMs,
  Int32 allowBadCertCallback,
);
typedef _TlsConnectTcpDart = int Function(
  int runtimeId,
  int requestId,
  Pointer<Int8> host,
  int port,
  int contextId,
  int timeoutMs,
  int allowBadCertCallback,
);

typedef _TlsConnectUnixNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Pointer<Int8> path,
  Pointer<Int8> serverName,
  Int64 contextId,
  Int64 timeoutMs,
  Int32 allowBadCertCallback,
);
typedef _TlsConnectUnixDart = int Function(
  int runtimeId,
  int requestId,
  Pointer<Int8> path,
  Pointer<Int8> serverName,
  int contextId,
  int timeoutMs,
  int allowBadCertCallback,
);

typedef _TlsBadCertDecisionNative = Int32 Function(
  Int64 runtimeId,
  Int64 decisionId,
  Int32 accept,
);
typedef _TlsBadCertDecisionDart = int Function(
  int runtimeId,
  int decisionId,
  int accept,
);

typedef _TlsSecureSocketNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Int64 socketId,
  Pointer<Int8> serverName,
  Int64 contextId,
  Int32 allowBadCertCallback,
);
typedef _TlsSecureSocketDart = int Function(
  int runtimeId,
  int requestId,
  int socketId,
  Pointer<Int8> serverName,
  int contextId,
  int allowBadCertCallback,
);

typedef _TlsSecureServerSocketNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Int64 socketId,
  Int64 contextId,
  Int32 requestClientCertificate,
  Int32 requireClientCertificate,
);
typedef _TlsSecureServerSocketDart = int Function(
  int runtimeId,
  int requestId,
  int socketId,
  int contextId,
  int requestClientCertificate,
  int requireClientCertificate,
);

typedef _SocketWriteNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Int64 socketId,
  Pointer<Uint8> data,
  IntPtr len,
);
typedef _SocketWriteDart = int Function(
  int runtimeId,
  int requestId,
  int socketId,
  Pointer<Uint8> data,
  int len,
);

typedef _SocketCloseNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Int64 socketId,
);
typedef _SocketCloseDart = int Function(
  int runtimeId,
  int requestId,
  int socketId,
);

typedef _TcpBindNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Pointer<Int8> host,
  Uint16 port,
);
typedef _TcpBindDart = int Function(
  int runtimeId,
  int requestId,
  Pointer<Int8> host,
  int port,
);

typedef _UnixBindNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Pointer<Int8> path,
  Int32 removeExisting,
);
typedef _UnixBindDart = int Function(
  int runtimeId,
  int requestId,
  Pointer<Int8> path,
  int removeExisting,
);

typedef _ServerCloseNative = Int32 Function(
  Int64 runtimeId,
  Int64 requestId,
  Int64 serverId,
);
typedef _ServerCloseDart = int Function(
  int runtimeId,
  int requestId,
  int serverId,
);

typedef _SecurityContextNewNative = Int64 Function();
typedef _SecurityContextNewDart = int Function();

typedef _SecurityContextFreeNative = Int32 Function(Int64 contextId);
typedef _SecurityContextFreeDart = int Function(int contextId);

typedef _SecurityContextPemNative = Int32 Function(
  Int64 contextId,
  Pointer<Uint8> bytes,
  IntPtr len,
);
typedef _SecurityContextPemDart = int Function(
  int contextId,
  Pointer<Uint8> bytes,
  int len,
);

final class _RustBindings {
  _RustBindings() : _lib = _openRustLibrary() {
    runtimeNew = _lib.lookupFunction<_RuntimeNewNative, _RuntimeNewDart>(
      'unixsock_rs_runtime_new',
    );
    runtimeFree = _lib.lookupFunction<_RuntimeFreeNative, _RuntimeFreeDart>(
      'unixsock_rs_runtime_free',
    );
    bufferFree = _lib.lookupFunction<_BufferFreeNative, _BufferFreeDart>(
      'unixsock_rs_buffer_free',
    );
    tcpConnect = _lib.lookupFunction<_TcpConnectNative, _TcpConnectDart>(
      'unixsock_rs_tcp_connect',
    );
    unixConnect = _lib.lookupFunction<_UnixConnectNative, _UnixConnectDart>(
      'unixsock_rs_unix_connect',
    );
    tlsConnectTcp =
        _lib.lookupFunction<_TlsConnectTcpNative, _TlsConnectTcpDart>(
            'unixsock_rs_tls_connect_tcp');
    tlsConnectUnix =
        _lib.lookupFunction<_TlsConnectUnixNative, _TlsConnectUnixDart>(
            'unixsock_rs_tls_connect_unix');
    tlsBadCertDecision =
        _lib.lookupFunction<_TlsBadCertDecisionNative, _TlsBadCertDecisionDart>(
            'unixsock_rs_tls_bad_cert_decision');
    tlsSecureSocket =
        _lib.lookupFunction<_TlsSecureSocketNative, _TlsSecureSocketDart>(
            'unixsock_rs_tls_secure_socket');
    tlsSecureServerSocket = _lib.lookupFunction<_TlsSecureServerSocketNative,
        _TlsSecureServerSocketDart>('unixsock_rs_tls_secure_server_socket');
    socketWrite = _lib.lookupFunction<_SocketWriteNative, _SocketWriteDart>(
      'unixsock_rs_socket_write',
    );
    socketClose = _lib.lookupFunction<_SocketCloseNative, _SocketCloseDart>(
      'unixsock_rs_socket_close',
    );
    tcpBind = _lib.lookupFunction<_TcpBindNative, _TcpBindDart>(
      'unixsock_rs_tcp_bind',
    );
    unixBind = _lib.lookupFunction<_UnixBindNative, _UnixBindDart>(
      'unixsock_rs_unix_bind',
    );
    serverClose = _lib.lookupFunction<_ServerCloseNative, _ServerCloseDart>(
      'unixsock_rs_server_close',
    );
    securityContextNew =
        _lib.lookupFunction<_SecurityContextNewNative, _SecurityContextNewDart>(
            'unixsock_rs_security_context_new');
    securityContextFree = _lib.lookupFunction<_SecurityContextFreeNative,
        _SecurityContextFreeDart>('unixsock_rs_security_context_free');
    securityContextSetTrustedPem =
        _lib.lookupFunction<_SecurityContextPemNative, _SecurityContextPemDart>(
            'unixsock_rs_security_context_set_trusted_certs_pem');
    securityContextSetCertChainPem =
        _lib.lookupFunction<_SecurityContextPemNative, _SecurityContextPemDart>(
            'unixsock_rs_security_context_use_certificate_chain_pem');
    securityContextSetPrivateKeyPem =
        _lib.lookupFunction<_SecurityContextPemNative, _SecurityContextPemDart>(
            'unixsock_rs_security_context_use_private_key_pem');
  }

  final DynamicLibrary _lib;

  late final _RuntimeNewDart runtimeNew;
  late final _RuntimeFreeDart runtimeFree;
  late final _BufferFreeDart bufferFree;
  late final _TcpConnectDart tcpConnect;
  late final _UnixConnectDart unixConnect;
  late final _TlsConnectTcpDart tlsConnectTcp;
  late final _TlsConnectUnixDart tlsConnectUnix;
  late final _TlsBadCertDecisionDart tlsBadCertDecision;
  late final _TlsSecureSocketDart tlsSecureSocket;
  late final _TlsSecureServerSocketDart tlsSecureServerSocket;
  late final _SocketWriteDart socketWrite;
  late final _SocketCloseDart socketClose;
  late final _TcpBindDart tcpBind;
  late final _UnixBindDart unixBind;
  late final _ServerCloseDart serverClose;
  late final _SecurityContextNewDart securityContextNew;
  late final _SecurityContextFreeDart securityContextFree;
  late final _SecurityContextPemDart securityContextSetTrustedPem;
  late final _SecurityContextPemDart securityContextSetCertChainPem;
  late final _SecurityContextPemDart securityContextSetPrivateKeyPem;
}

DynamicLibrary _openRustLibrary() {
  final String? explicitPath = Platform.environment['UNIXSOCK_RUST_LIB'];
  if (explicitPath != null && explicitPath.isNotEmpty) {
    return DynamicLibrary.open(explicitPath);
  }

  final List<String> names = <String>[
    if (Platform.isMacOS || Platform.isIOS) 'libunixsock_rust.dylib',
    if (Platform.isLinux || Platform.isAndroid) 'libunixsock_rust.so',
  ];

  Object? lastError;
  for (final String name in names) {
    try {
      return DynamicLibrary.open(name);
    } on Object catch (error) {
      lastError = error;
    }
  }

  try {
    return DynamicLibrary.process();
  } on Object catch (error) {
    lastError = error;
  }

  throw UnsupportedError(
    'Failed to load rust native library. '
    'Set UNIXSOCK_RUST_LIB=<absolute-lib-path>. '
    'lastError=$lastError',
  );
}

final class _NativeEvent {
  const _NativeEvent({
    required this.requestId,
    required this.event,
    required this.arg0,
    required this.arg1,
    this.data,
  });

  final int requestId;
  final int event;
  final int arg0;
  final int arg1;
  final Uint8List? data;
}

final class _SocketDispatch {
  _SocketDispatch({
    required this.onData,
    required this.onClosed,
    required this.onError,
  });

  final void Function(Uint8List data) onData;
  final void Function() onClosed;
  final void Function(Object error, StackTrace stackTrace) onError;
}

final class RustIoBackend {
  RustIoBackend._()
      : _bindings = _RustBindings(),
        _callback =
            NativeCallable<_EventNative>.listener(_onNativeEventStatic) {
    _callbackTarget = this;
    _runtimeId = _bindings.runtimeNew(_callback.nativeFunction);
    if (_runtimeId <= 0) {
      _callback.close();
      _callbackTarget = null;
      throw UnsupportedError('Failed to initialize rust async runtime');
    }
  }

  static RustIoBackend? _instance;

  static RustIoBackend get instance => _instance ??= RustIoBackend._();

  static RustIoBackend? _callbackTarget;

  static void _onNativeEventStatic(
    int requestId,
    int event,
    int arg0,
    int arg1,
    Pointer<Uint8> data,
    int len,
  ) {
    _callbackTarget?._onNativeEvent(requestId, event, arg0, arg1, data, len);
  }

  final _RustBindings _bindings;
  final NativeCallable<_EventNative> _callback;
  late final int _runtimeId;

  bool _disposed = false;
  int _nextRequestId = 1;
  final Map<int, Completer<_NativeEvent>> _pendingRequests =
      <int, Completer<_NativeEvent>>{};
  final Map<int, _SocketDispatch> _socketDispatches = <int, _SocketDispatch>{};
  final Map<int, void Function(int acceptedSocketId)> _serverAcceptHandlers =
      <int, void Function(int acceptedSocketId)>{};
  final Map<int, bool Function(X509Certificate certificate)?>
      _pendingBadCertificateCallbacks =
      <int, bool Function(X509Certificate certificate)?>{};

  void registerSocketDispatch(
    int socketId, {
    required void Function(Uint8List data) onData,
    required void Function() onClosed,
    required void Function(Object error, StackTrace stackTrace) onError,
  }) {
    _socketDispatches[socketId] = _SocketDispatch(
      onData: onData,
      onClosed: onClosed,
      onError: onError,
    );
  }

  void unregisterSocketDispatch(int socketId) {
    _socketDispatches.remove(socketId);
  }

  void registerServerAcceptHandler(
    int serverId,
    void Function(int acceptedSocketId) onAccept,
  ) {
    _serverAcceptHandlers[serverId] = onAccept;
  }

  void unregisterServerAcceptHandler(int serverId) {
    _serverAcceptHandlers.remove(serverId);
  }

  Future<int> connectTcp(
    String host,
    int port, {
    Duration? timeout,
  }) async {
    final Pointer<Utf8> hostPtr = host.toNativeUtf8();
    try {
      final _NativeEvent event = await _invokeRequest(
        timeout: _requestTimeout(timeout),
        dispatch: (int requestId) {
          return _bindings.tcpConnect(
            _runtimeId,
            requestId,
            hostPtr.cast<Int8>(),
            port,
            timeout?.inMilliseconds ?? 0,
          );
        },
      );
      if (event.event == _eventConnectOk) {
        return event.arg0;
      }
      throw _socketExceptionFromEvent('tcp connect failed', event);
    } finally {
      calloc.free(hostPtr);
    }
  }

  Future<int> connectUnix(
    String path, {
    Duration? timeout,
  }) async {
    final Pointer<Utf8> pathPtr = path.toNativeUtf8();
    try {
      final _NativeEvent event = await _invokeRequest(
        timeout: _requestTimeout(timeout),
        dispatch: (int requestId) {
          return _bindings.unixConnect(
            _runtimeId,
            requestId,
            pathPtr.cast<Int8>(),
            timeout?.inMilliseconds ?? 0,
          );
        },
      );
      if (event.event == _eventConnectOk) {
        return event.arg0;
      }
      throw _socketExceptionFromEvent('unix connect failed', event);
    } finally {
      calloc.free(pathPtr);
    }
  }

  Future<int> connectTlsTcp(
    String host,
    int port, {
    required int securityContextId,
    Duration? timeout,
    bool Function(X509Certificate certificate)? onBadCertificate,
  }) async {
    final Pointer<Utf8> hostPtr = host.toNativeUtf8();
    try {
      return _invokeTlsConnectRequest(
        timeout: _requestTimeout(timeout),
        onBadCertificate: onBadCertificate,
        dispatch: (int requestId) {
          return _bindings.tlsConnectTcp(
            _runtimeId,
            requestId,
            hostPtr.cast<Int8>(),
            port,
            securityContextId,
            timeout?.inMilliseconds ?? 0,
            onBadCertificate == null ? 0 : 1,
          );
        },
      );
    } finally {
      calloc.free(hostPtr);
    }
  }

  Future<int> connectTlsUnix(
    String path, {
    required String serverName,
    required int securityContextId,
    Duration? timeout,
    bool Function(X509Certificate certificate)? onBadCertificate,
  }) async {
    final Pointer<Utf8> pathPtr = path.toNativeUtf8();
    final Pointer<Utf8> serverNamePtr = serverName.toNativeUtf8();
    try {
      return _invokeTlsConnectRequest(
        timeout: _requestTimeout(timeout),
        onBadCertificate: onBadCertificate,
        dispatch: (int requestId) {
          return _bindings.tlsConnectUnix(
            _runtimeId,
            requestId,
            pathPtr.cast<Int8>(),
            serverNamePtr.cast<Int8>(),
            securityContextId,
            timeout?.inMilliseconds ?? 0,
            onBadCertificate == null ? 0 : 1,
          );
        },
      );
    } finally {
      calloc.free(pathPtr);
      calloc.free(serverNamePtr);
    }
  }

  Future<void> secureSocketTlsClient(
    int socketId, {
    required String serverName,
    required int securityContextId,
    bool Function(X509Certificate certificate)? onBadCertificate,
  }) async {
    final Pointer<Utf8> serverNamePtr = serverName.toNativeUtf8();
    try {
      await _invokeTlsCommandRequest(
        onBadCertificate: onBadCertificate,
        dispatch: (int requestId) {
          return _bindings.tlsSecureSocket(
            _runtimeId,
            requestId,
            socketId,
            serverNamePtr.cast<Int8>(),
            securityContextId,
            onBadCertificate == null ? 0 : 1,
          );
        },
      );
    } finally {
      calloc.free(serverNamePtr);
    }
  }

  Future<void> secureSocketTlsServer(
    int socketId, {
    required int securityContextId,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  }) async {
    await _invokeTlsCommandRequest(
      onBadCertificate: null,
      dispatch: (int requestId) {
        return _bindings.tlsSecureServerSocket(
          _runtimeId,
          requestId,
          socketId,
          securityContextId,
          requestClientCertificate ? 1 : 0,
          requireClientCertificate ? 1 : 0,
        );
      },
    );
  }

  Future<int> _invokeTlsConnectRequest({
    required int Function(int requestId) dispatch,
    required bool Function(X509Certificate certificate)? onBadCertificate,
    Duration? timeout,
  }) async {
    if (_disposed) {
      throw StateError('RustIoBackend is disposed');
    }
    final int requestId = _nextRequestId++;
    final Completer<_NativeEvent> completer = Completer<_NativeEvent>();
    _pendingRequests[requestId] = completer;
    _pendingBadCertificateCallbacks[requestId] = onBadCertificate;

    final int code = dispatch(requestId);
    if (code != 0) {
      _pendingRequests.remove(requestId);
      _pendingBadCertificateCallbacks.remove(requestId);
      throw SocketException('Native TLS dispatch failed with code=$code');
    }

    try {
      final _NativeEvent event = timeout == null
          ? await completer.future
          : await completer.future.timeout(timeout);
      if (event.event == _eventConnectOk) {
        return event.arg0;
      }
      throw _socketExceptionFromEvent('tls connect failed', event);
    } on TimeoutException {
      _pendingRequests.remove(requestId);
      throw SocketException(
          'Native TLS request timed out: requestId=$requestId');
    } finally {
      _pendingBadCertificateCallbacks.remove(requestId);
    }
  }

  Future<void> _invokeTlsCommandRequest({
    required int Function(int requestId) dispatch,
    required bool Function(X509Certificate certificate)? onBadCertificate,
    Duration? timeout,
  }) async {
    if (_disposed) {
      throw StateError('RustIoBackend is disposed');
    }
    final int requestId = _nextRequestId++;
    final Completer<_NativeEvent> completer = Completer<_NativeEvent>();
    _pendingRequests[requestId] = completer;
    _pendingBadCertificateCallbacks[requestId] = onBadCertificate;

    final int code = dispatch(requestId);
    if (code != 0) {
      _pendingRequests.remove(requestId);
      _pendingBadCertificateCallbacks.remove(requestId);
      throw SocketException('Native TLS dispatch failed with code=$code');
    }

    try {
      final _NativeEvent event = timeout == null
          ? await completer.future
          : await completer.future.timeout(timeout);
      if (event.event == _eventCommandOk) {
        return;
      }
      throw _socketExceptionFromEvent('tls secure failed', event);
    } on TimeoutException {
      _pendingRequests.remove(requestId);
      throw SocketException(
          'Native TLS request timed out: requestId=$requestId');
    } finally {
      _pendingBadCertificateCallbacks.remove(requestId);
    }
  }

  Future<({int serverId, int port})> bindTcp(String host, int port) async {
    final Pointer<Utf8> hostPtr = host.toNativeUtf8();
    try {
      final _NativeEvent event = await _invokeRequest(
        dispatch: (int requestId) {
          return _bindings.tcpBind(
            _runtimeId,
            requestId,
            hostPtr.cast<Int8>(),
            port,
          );
        },
      );
      if (event.event == _eventServerBound) {
        return (serverId: event.arg0, port: event.arg1);
      }
      throw _socketExceptionFromEvent('tcp bind failed', event);
    } finally {
      calloc.free(hostPtr);
    }
  }

  Future<int> bindUnix(
    String path, {
    bool removeExisting = true,
  }) async {
    final Pointer<Utf8> pathPtr = path.toNativeUtf8();
    try {
      final _NativeEvent event = await _invokeRequest(
        dispatch: (int requestId) {
          return _bindings.unixBind(
            _runtimeId,
            requestId,
            pathPtr.cast<Int8>(),
            removeExisting ? 1 : 0,
          );
        },
      );
      if (event.event == _eventServerBound) {
        return event.arg0;
      }
      throw _socketExceptionFromEvent('unix bind failed', event);
    } finally {
      calloc.free(pathPtr);
    }
  }

  Future<void> writeSocket(int socketId, Uint8List data) async {
    final Pointer<Uint8> ptr = calloc<Uint8>(data.length);
    try {
      if (data.isNotEmpty) {
        ptr.asTypedList(data.length).setAll(0, data);
      }
      final _NativeEvent event = await _invokeRequest(
        dispatch: (int requestId) {
          return _bindings.socketWrite(
            _runtimeId,
            requestId,
            socketId,
            ptr,
            data.length,
          );
        },
      );
      if (event.event == _eventWriteOk) {
        return;
      }
      throw _socketExceptionFromEvent('socket write failed', event);
    } finally {
      calloc.free(ptr);
    }
  }

  Future<void> closeSocket(int socketId) async {
    final _NativeEvent event = await _invokeRequest(
      dispatch: (int requestId) =>
          _bindings.socketClose(_runtimeId, requestId, socketId),
    );
    if (event.event == _eventCommandOk) {
      return;
    }
    throw _socketExceptionFromEvent('socket close failed', event);
  }

  Future<void> closeServer(int serverId) async {
    final _NativeEvent event = await _invokeRequest(
      dispatch: (int requestId) =>
          _bindings.serverClose(_runtimeId, requestId, serverId),
    );
    if (event.event == _eventCommandOk) {
      return;
    }
    throw _socketExceptionFromEvent('server close failed', event);
  }

  int createSecurityContext() {
    final int id = _bindings.securityContextNew();
    if (id <= 0) {
      throw StateError('Failed to create rust security context');
    }
    return id;
  }

  void freeSecurityContext(int contextId) {
    _bindings.securityContextFree(contextId);
  }

  void setTrustedCertsPem(int contextId, Uint8List pem) {
    _setSecurityContextPem(
      contextId,
      pem,
      _bindings.securityContextSetTrustedPem,
      'set trusted certificates',
    );
  }

  void setCertificateChainPem(int contextId, Uint8List pem) {
    _setSecurityContextPem(
      contextId,
      pem,
      _bindings.securityContextSetCertChainPem,
      'set certificate chain',
    );
  }

  void setPrivateKeyPem(int contextId, Uint8List pem) {
    _setSecurityContextPem(
      contextId,
      pem,
      _bindings.securityContextSetPrivateKeyPem,
      'set private key',
    );
  }

  void _setSecurityContextPem(
    int contextId,
    Uint8List pem,
    _SecurityContextPemDart setter,
    String action,
  ) {
    final Pointer<Uint8> ptr = calloc<Uint8>(pem.length);
    try {
      if (pem.isNotEmpty) {
        ptr.asTypedList(pem.length).setAll(0, pem);
      }
      final int code = setter(contextId, ptr, pem.length);
      if (code != 0) {
        throw ArgumentError.value(
          contextId,
          'contextId',
          'RustSecurityContext failed to $action (native code=$code)',
        );
      }
    } finally {
      calloc.free(ptr);
    }
  }

  void dispose() {
    if (_disposed) {
      return;
    }
    _disposed = true;
    _callbackTarget = null;
    _pendingRequests.clear();
    _pendingBadCertificateCallbacks.clear();
    _socketDispatches.clear();
    _serverAcceptHandlers.clear();
    _bindings.runtimeFree(_runtimeId);
    _callback.close();
  }

  Future<_NativeEvent> _invokeRequest({
    required int Function(int requestId) dispatch,
    Duration? timeout,
  }) async {
    if (_disposed) {
      throw StateError('RustIoBackend is disposed');
    }
    final int requestId = _nextRequestId++;
    final Completer<_NativeEvent> completer = Completer<_NativeEvent>();
    _pendingRequests[requestId] = completer;

    final int code = dispatch(requestId);
    if (code != 0) {
      _pendingRequests.remove(requestId);
      throw SocketException('Native dispatch failed with code=$code');
    }

    try {
      if (timeout != null) {
        return await completer.future.timeout(timeout);
      }
      return await completer.future;
    } on TimeoutException {
      _pendingRequests.remove(requestId);
      throw SocketException('Native request timed out: requestId=$requestId');
    }
  }

  Duration? _requestTimeout(Duration? timeout) {
    if (timeout == null) {
      return null;
    }
    return timeout + const Duration(milliseconds: 250);
  }

  void _onNativeEvent(
    int requestId,
    int event,
    int arg0,
    int arg1,
    Pointer<Uint8> data,
    int len,
  ) {
    if (_disposed) {
      return;
    }

    Uint8List? payload;
    if (len > 0 && data != nullptr) {
      payload = Uint8List.fromList(data.asTypedList(len));
      _bindings.bufferFree(data, len);
    }

    if (event == _eventTlsBadCert) {
      bool accepted = false;
      final bool Function(X509Certificate certificate)? callback =
          _pendingBadCertificateCallbacks[requestId];
      if (callback != null && payload != null) {
        try {
          accepted = callback(RustX509Certificate.fromDer(payload));
        } catch (_) {
          accepted = false;
        }
      }
      _bindings.tlsBadCertDecision(_runtimeId, arg0, accepted ? 1 : 0);
      return;
    }

    final _NativeEvent nativeEvent = _NativeEvent(
      requestId: requestId,
      event: event,
      arg0: arg0,
      arg1: arg1,
      data: payload,
    );

    final Completer<_NativeEvent>? pending = _pendingRequests.remove(requestId);
    if (pending != null && !pending.isCompleted) {
      pending.complete(nativeEvent);
      return;
    }

    if (event == _eventSocketData) {
      final _SocketDispatch? dispatch = _socketDispatches[arg0];
      if (dispatch != null && payload != null) {
        dispatch.onData(payload);
      }
      return;
    }
    if (event == _eventSocketClosed) {
      _socketDispatches[arg0]?.onClosed();
      return;
    }
    if (event == _eventSocketError) {
      _socketDispatches[arg0]?.onError(
        SocketException(_decodeMessage(payload)),
        StackTrace.current,
      );
      return;
    }
    if (event == _eventServerAccept) {
      _serverAcceptHandlers[arg0]?.call(arg1);
      return;
    }
    if (event == _eventServerClosed) {
      _serverAcceptHandlers.remove(arg0);
      return;
    }
    if (event == _eventServerError) {
      return;
    }
  }
}

String _decodeMessage(Uint8List? bytes) {
  if (bytes == null || bytes.isEmpty) {
    return 'native error';
  }
  return String.fromCharCodes(bytes);
}

SocketException _socketExceptionFromEvent(String prefix, _NativeEvent event) {
  return SocketException('$prefix: ${_decodeMessage(event.data)}');
}

/// Minimal X509Certificate bridge for `onBadCertificate` callback.
class RustX509Certificate implements X509Certificate {
  RustX509Certificate._(this._der);

  factory RustX509Certificate.fromDer(Uint8List der) {
    return RustX509Certificate._(Uint8List.fromList(der));
  }

  final Uint8List _der;

  @override
  Uint8List get der => Uint8List.fromList(_der);

  @override
  String get pem => _derToPem(_der);

  @override
  Uint8List get sha1 => Uint8List(0);

  @override
  String get subject => 'unknown';

  @override
  String get issuer => 'unknown';

  @override
  DateTime get startValidity =>
      DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

  @override
  DateTime get endValidity =>
      DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);
}

String _derToPem(Uint8List der) {
  final String encoded = base64.encode(der);
  final StringBuffer out = StringBuffer('-----BEGIN CERTIFICATE-----\n');
  for (int i = 0; i < encoded.length; i += 64) {
    final int end = (i + 64 < encoded.length) ? i + 64 : encoded.length;
    out.writeln(encoded.substring(i, end));
  }
  out.write('-----END CERTIFICATE-----\n');
  return out.toString();
}

# unixsock_rust

`unixsock_rust` 是 `unixsock` 的 Rust 异步底座（当前已实现）：

- `tokio` 运行时统一承载异步 tcp/unix socket
- `rustls`/`rustls-pemfile` 实现客户端 TLS 握手与证书上下文
- 通过事件回调把 `onBadCertificate` 决策交给 Dart 层
- C ABI 通过 Dart FFI 调用

## 构建

```bash
cd rust
cargo build
```

产物示例（macOS）：

`target/debug/libunixsock_rust.dylib`

## 当前 ABI

- `unixsock_rs_runtime_new`
- `unixsock_rs_runtime_free`
- `unixsock_rs_buffer_free`
- `unixsock_rs_tcp_connect`
- `unixsock_rs_unix_connect`
- `unixsock_rs_tls_connect_tcp`
- `unixsock_rs_tls_connect_unix`
- `unixsock_rs_tls_bad_cert_decision`
- `unixsock_rs_tls_secure_socket`
- `unixsock_rs_tls_secure_server_socket`
- `unixsock_rs_socket_write`
- `unixsock_rs_socket_close`
- `unixsock_rs_tcp_bind`
- `unixsock_rs_unix_bind`
- `unixsock_rs_server_close`
- `unixsock_rs_security_context_*`

当前已覆盖 `SecureSocket.connect/startConnect/secure/secureServer` 所需的 Rust 侧 TLS 握手能力。

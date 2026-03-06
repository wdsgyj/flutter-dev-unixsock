## Unreleased

- Removed legacy Dart-side `UnixSocket` / `UnixServerSocket` / `UnixSecureSocket` implementations.
- Kept only Rust-backed Dart wrappers: `RustSocket`, `RustServerSocket`, `RustSecurityContext`, `RustSecureSocket`.
- Updated tests and example to use Rust wrappers only.
- Completed Rust FFI wrapper APIs for TLS socket upgrade: `RustSecureSocket.secure/secureServer` now work on existing `RustSocket`.

## 0.1.0

- Initial release.
- Added `UnixSocket` (`Socket` subtype) based on libc FFI.
- Added `UnixServerSocket` (`ServerSocket` subtype) based on libc FFI.
- Added `UnixSecureSocket` (`SecureSocket` subtype) for TLS-over-UnixSocket with `connect/startConnect/secure/secureServer` APIs.
- Added experimental Rust async foundation under `rust/` (tokio + rustls): runtime/event ABI, tcp/unix connect/bind/read/write, and Dart FFI wrappers (`RustSocket`/`RustServerSocket`/`RustSecurityContext`).
- Added rustls client TLS handshake path in Rust with Dart-side bad-certificate decision callback wiring (`RustSecureSocket.connect/startConnect` + `onBadCertificate` bridge).
- Non-blocking event loop with `poll`; Linux/Android use `SOCK_NONBLOCK + accept4` directly, Apple platforms use a C shim for non-block flags.
- Refactored polling model to a shared single Reactor isolate with reference-counted lifecycle.
- Added package tests and `example/test` echo verification.

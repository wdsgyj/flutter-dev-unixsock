## 0.1.0

- Initial release.
- Added `UnixSocket` (`Socket` subtype) based on libc FFI.
- Added `UnixServerSocket` (`ServerSocket` subtype) based on libc FFI.
- Non-blocking event loop with `poll`; Linux/Android use `SOCK_NONBLOCK + accept4` directly, Apple platforms use a C shim for non-block flags.
- Refactored polling model to a shared single Reactor isolate with reference-counted lifecycle.
- Added package tests and `example/test` echo verification.

# unixsock

Rust + Dart FFI 的跨平台 Socket 封装，Dart 侧仅保留 Rust wrapper：

- `RustSocket` implements `dart:io` `Socket`（TCP/Unix）
- `RustServerSocket` implements `dart:io` `ServerSocket`（TCP/Unix）
- `RustSecurityContext`（rustls 证书上下文）
- `RustSecureSocket` implements `dart:io` `SecureSocket`（当前支持 `connect/startConnect`）

底层在 Rust 侧实现：

- `tokio` 异步运行时
- `rustls` TLS 握手与证书校验
- `onBadCertificate` 回调由 Dart 侧决策，结果回传 Rust

## 平台

- Android
- iOS
- macOS
- Linux

## 构建 Rust 动态库

```bash
cd rust
cargo build
```

运行 Dart/Flutter 时可通过环境变量指定动态库路径：

```bash
UNIXSOCK_RUST_LIB=/abs/path/to/libunixsock_rust.dylib
```

Linux/Android 使用 `.so`。

## 用法

```dart
import 'dart:convert';
import 'dart:io';

import 'package:unixsock/unixsock.dart';

Future<void> main() async {
  final server = await RustServerSocket.bind('/tmp/rust_echo.sock', 0);
  server.listen((socket) {
    socket.listen((data) => socket.add(data));
  });

  final client = await RustSocket.connect('/tmp/rust_echo.sock', 0);
  client.add(utf8.encode('hello from rust backend'));
  final echoed = await client.first;
  print(utf8.decode(echoed));

  await client.close();
  await server.close();
}
```

TLS 客户端示例：

```dart
import 'package:unixsock/unixsock.dart';

final context = RustSecurityContext(withTrustedRoots: false)
  ..setTrustedCertificatesBytes(certPemBytes);

final secure = await RustSecureSocket.connect(
  'example.com',
  443,
  context: context,
  onBadCertificate: (cert) {
    return false;
  },
);
```

说明：`RustSecureSocket.secure/secureServer` 已支持基于 `RustSocket` 的连接升级。

## 测试

```bash
dart test
```

example:

```bash
cd example
flutter test
```

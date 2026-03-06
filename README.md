# unixsock

基于 Dart FFI 直接调用 `libc` 原语（`socket/bind/listen/accept/connect/recv/send/poll`）实现 Unix Domain Socket，提供与 Dart 标准库一致的使用方式：

- `UnixSocket` implements `dart:io` 的 `Socket`
- `UnixServerSocket` implements `dart:io` 的 `ServerSocket`
- 全程非阻塞（`SOCK_NONBLOCK/accept4` 或 C shim + `poll` 事件循环），不会阻塞 isolate 线程
- 规避 Dart FFI variadic 问题：Linux/Android 使用 `SOCK_NONBLOCK + accept4`，Apple 平台通过插件内 C shim 设置 non-block
- 底层使用单例 Reactor isolate 复用 `poll` 事件循环；socket 数量从 `0 -> 1` 时创建，回到 `0` 时自动释放

## 平台

- Android
- iOS
- macOS
- Linux

## 原生构建

这是一个 Flutter FFI plugin package，包含以下平台构建目录：

- `android/`
- `ios/`
- `macos/`
- `linux/`
- 共享 C 源码在 `src/`

## 安装

```yaml
dependencies:
  unixsock:
    path: ../unixsock
```

## 用法

```dart
import 'dart:convert';
import 'dart:io';

import 'package:unixsock/unixsock.dart';

Future<void> main() async {
  final server = await UnixServerSocket.bind('/tmp/unixsock_echo.sock');
  server.listen((Socket client) {
    client.listen((data) => client.add(data));
  });

  final client = await UnixSocket.connect('/tmp/unixsock_echo.sock');
  client.add(utf8.encode('hello'));

  final echoed = await client.first;
  print(utf8.decode(echoed));

  await client.close();
  await server.close();
}
```

## Example

运行 Flutter example app：

```bash
cd example
flutter run -d macos
```

也可切换到 `android/ios/linux` 目标设备运行。

## 测试

项目测试：

```bash
dart test
```

example 测试：

```bash
cd example
flutter test
```

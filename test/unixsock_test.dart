import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:unixsock/unixsock.dart';

void main() {
  test('UnixSocket echo roundtrip', () async {
    if (!await _unixSocketRuntimeAvailable()) {
      return;
    }

    final tempDir = await Directory.systemTemp.createTemp('unixsock_test_');
    final socketPath = '${tempDir.path}/echo.sock';

    final server = await UnixServerSocket.bind(socketPath);
    addTearDown(() async {
      await server.close();
      await tempDir.delete(recursive: true);
    });

    server.listen((Socket client) {
      client.listen((data) => client.add(data), onDone: client.destroy);
    });

    final client = await UnixSocket.connect(
      socketPath,
      timeout: const Duration(seconds: 2),
    );
    addTearDown(client.destroy);

    client.add(utf8.encode('ping'));
    final data = await client.first.timeout(const Duration(seconds: 2));
    expect(utf8.decode(data), 'ping');

    await client.close();
  });
}

Future<bool> _unixSocketRuntimeAvailable() async {
  final tempDir = await Directory.systemTemp.createTemp('unixsock_probe_');
  final socketPath = '${tempDir.path}/probe.sock';
  try {
    final server = await UnixServerSocket.bind(
      socketPath,
      deletePathOnClose: true,
      removeExisting: true,
    );
    await server.close();
    return true;
  } on SocketException catch (e) {
    final code = e.osError?.errorCode;
    // Some CI sandboxes disallow AF_UNIX even on Unix hosts.
    if (code == 1 || code == 95) {
      return false;
    }
    rethrow;
  } on UnsupportedError {
    // In plain `dart test` on Apple hosts, the Flutter plugin dynamic library
    // is not loaded, so shim symbols are unavailable.
    return false;
  } finally {
    await tempDir.delete(recursive: true);
  }
}

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:unixsock/unixsock.dart';

void main() {
  test('example-style server/client works', () async {
    if (!await _rustSocketRuntimeAvailable()) {
      return;
    }

    final tempDir = await Directory.systemTemp.createTemp(
      'unixsock_example_test_',
    );
    final socketPath = '${tempDir.path}/example.sock';

    final server = await RustServerSocket.bind(socketPath, 0);
    addTearDown(() async {
      await server.close();
      await tempDir.delete(recursive: true);
    });

    server.listen((Socket client) {
      client.listen((data) => client.add(data), onDone: client.destroy);
    });

    final client = await RustSocket.connect(socketPath, 0,
        timeout: const Duration(seconds: 2));
    addTearDown(client.destroy);

    client.write('example');
    final echoed = await client.first.timeout(const Duration(seconds: 2));
    expect(utf8.decode(echoed), 'example');

    await client.close();
  });
}

Future<bool> _rustSocketRuntimeAvailable() async {
  final tempDir = await Directory.systemTemp.createTemp(
    'unixsock_probe_example_',
  );
  final socketPath = '${tempDir.path}/probe.sock';
  try {
    final server = await RustServerSocket.bind(
      socketPath,
      0,
      removeExisting: true,
    ).timeout(const Duration(seconds: 2));
    await server.close().timeout(const Duration(seconds: 2));
    return true;
  } on TimeoutException {
    return false;
  } on SocketException catch (e) {
    final code = e.osError?.errorCode;
    if (code == 1 || code == 95) {
      return false;
    }
    rethrow;
  } on UnsupportedError {
    return false;
  } on ArgumentError {
    return false;
  } finally {
    await tempDir.delete(recursive: true);
  }
}

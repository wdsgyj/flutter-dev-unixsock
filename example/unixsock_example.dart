import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:unixsock/unixsock.dart';

Future<void> main() async {
  final Directory tempDir = await Directory.systemTemp.createTemp(
    'unixsock_example_',
  );
  final String socketPath = '${tempDir.path}/echo.sock';

  final server = await RustServerSocket.bind(socketPath, 0);
  server.listen((Socket client) {
    client.listen(
      (data) => client.add(data),
      onDone: client.destroy,
      onError: (Object error, StackTrace stackTrace) {
        stderr.writeln('server client error: $error');
      },
    );
  });

  final client = await RustSocket.connect(socketPath, 0,
      timeout: const Duration(seconds: 2));
  client.add(utf8.encode('hello unix ffi'));

  final reply = await client.first.timeout(const Duration(seconds: 2));
  stdout.writeln('reply: ${utf8.decode(reply)}');

  await client.close();
  await server.close();
  await tempDir.delete(recursive: true);
}

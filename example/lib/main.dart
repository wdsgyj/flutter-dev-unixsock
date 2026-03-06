import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:unixsock/unixsock.dart';

void main() {
  runApp(const UnixsockExampleApp());
}

class UnixsockExampleApp extends StatelessWidget {
  const UnixsockExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'unixsock example',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF0A7C66)),
      ),
      home: const EchoDemoPage(),
    );
  }
}

class EchoDemoPage extends StatefulWidget {
  const EchoDemoPage({super.key});

  @override
  State<EchoDemoPage> createState() => _EchoDemoPageState();
}

class _EchoDemoPageState extends State<EchoDemoPage> {
  String _status = 'Idle';
  String _details = 'Tap the button to run a Rust socket echo roundtrip.';
  bool _running = false;

  Future<void> _runEcho() async {
    if (_running) {
      return;
    }
    if (!(Platform.isAndroid ||
        Platform.isIOS ||
        Platform.isLinux ||
        Platform.isMacOS)) {
      setState(() {
        _status = 'Unsupported';
        _details = 'This demo supports Android/iOS/Linux/macOS only.';
      });
      return;
    }

    setState(() {
      _running = true;
      _status = 'Running';
      _details = 'Creating server and client sockets...';
    });

    Directory? tempDir;
    RustServerSocket? server;
    StreamSubscription<Socket>? serverSub;
    RustSocket? client;

    try {
      tempDir = await Directory.systemTemp.createTemp('uxs_');
      final socketPath = '${tempDir.path}/echo.sock';

      server = await RustServerSocket.bind(socketPath, 0);
      serverSub = server.listen((Socket socket) {
        socket.listen(
          (data) => socket.add(data),
          onDone: socket.destroy,
          onError: (Object _, StackTrace __) {
            socket.destroy();
          },
        );
      });

      client = await RustSocket.connect(
        socketPath,
        0,
        timeout: const Duration(seconds: 2),
      );

      const payload = 'hello from flutter ffi';
      client.add(utf8.encode(payload));
      final echoedBytes = await client.first.timeout(
        const Duration(seconds: 2),
      );
      final echoed = utf8.decode(echoedBytes);

      if (echoed != payload) {
        throw StateError('echo mismatch: "$echoed"');
      }

      setState(() {
        _status = 'Success';
        _details = 'Roundtrip ok: $echoed';
      });
    } catch (error) {
      setState(() {
        _status = 'Error';
        _details = '$error';
      });
    } finally {
      try {
        await client?.close();
      } catch (_) {
        client?.destroy();
      }
      await serverSub?.cancel();
      await server?.close();
      if (tempDir != null) {
        await tempDir.delete(recursive: true);
      }

      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('unixsock example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Status: $_status',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 12),
            Text(_details),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _running ? null : _runEcho,
              icon: _running
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow),
              label: const Text('Run Echo Test'),
            ),
          ],
        ),
      ),
    );
  }
}

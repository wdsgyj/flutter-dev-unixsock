import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:unixsock/unixsock.dart';

void main() {
  test('RustSocket unix echo roundtrip', () async {
    if (!await _rustIoRuntimeAvailable()) {
      return;
    }

    final tempDir = await Directory.systemTemp.createTemp('unixsock_test_');
    final socketPath = '${tempDir.path}/echo.sock';

    final server = await RustServerSocket.bind(socketPath, 0);
    addTearDown(() async {
      await server.close();
      await tempDir.delete(recursive: true);
    });

    server.listen((Socket client) {
      client.listen((data) => client.add(data), onDone: client.destroy);
    });

    final client = await RustSocket.connect(
      socketPath,
      0,
      timeout: const Duration(seconds: 2),
    );
    addTearDown(client.destroy);

    client.add(utf8.encode('ping'));
    final data = await client.first.timeout(const Duration(seconds: 2));
    expect(utf8.decode(data), 'ping');

    await client.close();
  });

  test('RustSecureSocket.connect accepts bad cert when callback returns true',
      () async {
    if (!await _rustTlsRuntimeAvailable()) {
      return;
    }

    final SecurityContext serverContext =
        SecurityContext(withTrustedRoots: false)
          ..useCertificateChainBytes(utf8.encode(_serverCertificatePem))
          ..usePrivateKeyBytes(utf8.encode(_serverPrivateKeyPem));

    final server = await SecureServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      serverContext,
      supportedProtocols: const <String>['uxs/1'],
    );
    addTearDown(server.close);

    server.listen((SecureSocket client) {
      client.listen((List<int> data) => client.add(data),
          onDone: client.destroy);
    });

    bool callbackCalled = false;
    final RustSecureSocket socket = await RustSecureSocket.connect(
      InternetAddress.loopbackIPv4.address,
      server.port,
      timeout: const Duration(seconds: 3),
      onBadCertificate: (X509Certificate cert) {
        callbackCalled = true;
        expect(cert.pem, contains('BEGIN CERTIFICATE'));
        return true;
      },
    );
    addTearDown(socket.destroy);
    expect(callbackCalled, isTrue);

    socket.write('rust-accept');
    final response = await socket.first.timeout(const Duration(seconds: 2));
    expect(utf8.decode(response), 'rust-accept');
    await socket.close();
  });

  test('RustSecureSocket.connect rejects bad cert when callback returns false',
      () async {
    if (!await _rustTlsRuntimeAvailable()) {
      return;
    }

    final SecurityContext serverContext =
        SecurityContext(withTrustedRoots: false)
          ..useCertificateChainBytes(utf8.encode(_serverCertificatePem))
          ..usePrivateKeyBytes(utf8.encode(_serverPrivateKeyPem));

    final server = await SecureServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      serverContext,
    );
    addTearDown(server.close);

    server.listen((SecureSocket client) {
      client.listen((List<int> data) => client.add(data),
          onDone: client.destroy);
    });

    bool callbackCalled = false;
    await expectLater(
      RustSecureSocket.connect(
        InternetAddress.loopbackIPv4.address,
        server.port,
        timeout: const Duration(seconds: 3),
        onBadCertificate: (_) {
          callbackCalled = true;
          return false;
        },
      ),
      throwsA(isA<SocketException>()),
    );
    expect(callbackCalled, isTrue);
  });

  test('RustSecureSocket.secure/secureServer upgrade existing RustSocket',
      () async {
    if (!await _rustTlsRuntimeAvailable()) {
      return;
    }

    final RustSecurityContext serverContext =
        RustSecurityContext(withTrustedRoots: false)
          ..useCertificateChainBytes(utf8.encode(_serverCertificatePem))
          ..usePrivateKeyBytes(utf8.encode(_serverPrivateKeyPem));
    addTearDown(serverContext.dispose);

    final RustServerSocket server =
        await RustServerSocket.bind(InternetAddress.loopbackIPv4.address, 0);
    final List<Object> serverErrors = <Object>[];
    final StreamSubscription<Socket> serverSubscription = server.listen(
      (Socket socket) {
        unawaited(() async {
          RustSecureSocket? secure;
          try {
            secure = await RustSecureSocket.secureServer(
              socket,
              serverContext,
            );
            await for (final chunk in secure) {
              secure.add(chunk);
            }
          } catch (error) {
            serverErrors.add(error);
            socket.destroy();
          } finally {
            if (secure != null) {
              await secure.close();
            }
          }
        }());
      },
      onError: (Object error, StackTrace stackTrace) {
        serverErrors.add(error);
      },
    );
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close();
    });

    final RustSocket plain = await RustSocket.connect(
      InternetAddress.loopbackIPv4.address,
      server.port,
      timeout: const Duration(seconds: 2),
    );
    addTearDown(plain.destroy);

    bool callbackCalled = false;
    final RustSecureSocket client = await RustSecureSocket.secure(
      plain,
      host: 'localhost',
      onBadCertificate: (X509Certificate cert) {
        callbackCalled = true;
        expect(cert.pem, contains('BEGIN CERTIFICATE'));
        return true;
      },
    );
    addTearDown(client.destroy);
    expect(callbackCalled, isTrue);

    client.write('upgrade');
    final response = await client.first.timeout(const Duration(seconds: 2));
    expect(utf8.decode(response), 'upgrade');
    expect(serverErrors, isEmpty);
    await client.close();
  });

  test('RustSecureSocket.startConnect returns a usable ConnectionTask',
      () async {
    if (!await _rustTlsRuntimeAvailable()) {
      return;
    }

    final SecurityContext serverContext =
        SecurityContext(withTrustedRoots: false)
          ..useCertificateChainBytes(utf8.encode(_serverCertificatePem))
          ..usePrivateKeyBytes(utf8.encode(_serverPrivateKeyPem));

    final server = await SecureServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      serverContext,
    );
    addTearDown(server.close);

    server.listen((SecureSocket client) {
      client.listen((List<int> data) => client.add(data),
          onDone: client.destroy);
    });

    final ConnectionTask<RustSecureSocket> task =
        await RustSecureSocket.startConnect(
      InternetAddress.loopbackIPv4.address,
      server.port,
      onBadCertificate: (_) => true,
    );
    final RustSecureSocket client =
        await task.socket.timeout(const Duration(seconds: 3));
    addTearDown(client.destroy);

    client.write('task');
    final response = await client.first.timeout(const Duration(seconds: 2));
    expect(utf8.decode(response), 'task');
    await client.close();
  });
}

Future<bool> _rustIoRuntimeAvailable() async {
  final tempDir = await Directory.systemTemp.createTemp('unixsock_probe_');
  final socketPath = '${tempDir.path}/probe.sock';
  try {
    final RustServerSocket server = await RustServerSocket.bind(
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

Future<bool> _rustTlsRuntimeAvailable() async {
  if (!await _rustIoRuntimeAvailable()) {
    return false;
  }

  try {
    final RustSecurityContext context =
        RustSecurityContext(withTrustedRoots: false);
    context.dispose();
    return true;
  } on TimeoutException {
    return false;
  } on UnsupportedError {
    return false;
  } on ArgumentError {
    return false;
  }
}

const String _serverCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUKjYP8duQJiWSNykfvfEw9YfXM1QwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNdW5peHNvY2stdGVzdDAeFw0yNjAzMDYwODM2MzlaFw0y
NzAzMDYwODM2MzlaMBgxFjAUBgNVBAMMDXVuaXhzb2NrLXRlc3QwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQxiRgt25xWLrX34MbvsQpYpa7I7T7cHyp
d1DlmnkvlyWztYxwNeKNenTihMp6m5wD78zzyD+Iwkl80ERcBTdqe6fw2l7ifIGz
N0d4811uoBgNeQ8Viu9GKgD0wzpYR2c5DZWhawaomzUmiWVr4ZzXlK/F64arB19w
KCNvV/TO8EuOmFpyiSojeIAU8TmSzv2YX4UhL6opoCmYrI8si9yu+6JlHQtDzFpe
7cMIqTFdbvEdI0OWhEAmckciYm3WTvyL88cC79TDZEoxQDdPOEHp62lDdz4mr626
GcewTI8ruZT2YH/Ao731fFDnLzB/wHAfsReIWmjTaUjz6nt40+33AgMBAAGjUzBR
MB0GA1UdDgQWBBTh9u7mw24jnSUlwX39T/zCgkrINTAfBgNVHSMEGDAWgBTh9u7m
w24jnSUlwX39T/zCgkrINTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBwDE4aFPbsvH5KkgY9uP16WyPgsTDkk6GRcVLi5g6q3JKwIuRzyeIDmiii
8xna0MO02G8+T8m95M0BtpMvtwyaURm+VNmXW13nJTMHJfh5/9GKmfcLDnFzxw+y
02ouEq4xPMoohpkbx7MXVyL5qW6Q3bvBkL1FuAHXUqOjlaaVTZhGQyg+zf0C42U/
KDg/l25Lf1CfcmGeEmg2hVE9YOYOxtYdfaEdKc1w8Wknq0sDrPYyBVlEkbAXWRen
d44XNDeiCKHP71URADEDBBVjAzmFWgHnqr4ylnVSBpb+mN8kzOO27DDJo2hIUo1U
u9QrUvBffsLrNWojtMx/gz+dfuxI
-----END CERTIFICATE-----
''';

const String _serverPrivateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCQxiRgt25xWLrX
34MbvsQpYpa7I7T7cHypd1DlmnkvlyWztYxwNeKNenTihMp6m5wD78zzyD+Iwkl8
0ERcBTdqe6fw2l7ifIGzN0d4811uoBgNeQ8Viu9GKgD0wzpYR2c5DZWhawaomzUm
iWVr4ZzXlK/F64arB19wKCNvV/TO8EuOmFpyiSojeIAU8TmSzv2YX4UhL6opoCmY
rI8si9yu+6JlHQtDzFpe7cMIqTFdbvEdI0OWhEAmckciYm3WTvyL88cC79TDZEox
QDdPOEHp62lDdz4mr626GcewTI8ruZT2YH/Ao731fFDnLzB/wHAfsReIWmjTaUjz
6nt40+33AgMBAAECggEADGPgziQ0wApI0gaE2SreQpp3mE7fLjEQ14y+GtW5xGW/
qh3XW0J0AAljF9XR4boP7qhRwUAPQUbmH4KlhGiajF2b4GRCqvMz7ctv2FKfru2Q
UWrdwclmXqS5TeP9dNEGQl7pbOtUzQ5Hd2Ov5JKQ/URHjNKc77s4TZ1/IYgvYUcU
0F43re8V3gXaAvb/M4SH8uD5TOAKwqKHvrYPHP/vvPIfXOgRYBpmuoQDnvQLExkT
HlIXF9G+62GYSgYpRlCd+IVefI0rlemtbT886TexCgXYtfu+I0e+41dJGuDVUbt4
f2q1LWf+ixXuSBvMLSNljAYxgm98Ul+NIUdGbQm95QKBgQDJ2zjS/Se8K28KHV+6
z/fNtWg4tAvpjObV5nLRHCqGMVvaouFyq/ykGDDqCJL9TdcCFbj0z1fBNxJQJKDg
DdJSCdJhe7L1yUx4C3W6HMiCaW8ISRdx5bx7JF0sABXvokztuQu0FLbTgD3klRl4
rowK7cj7HF8yUQR0xvOsAulafQKBgQC3m0XI4y8QlG98JwFo+0BfCggf8Ikp0yeB
W57i20nSO3rH3xrN7vXWr6aPdPYnUf0VFY4KvqVkMMOveNFLXfpf7Cowo90Rtk9S
VmKIEcwvTuC+P4okCbpnPpr1ALi5ojPbLZNEmm3TwzO532meTlwv2a8zfuZ24QgF
zd9qwHcggwKBgCIDSYDr3V0sqGo45t+QmX3VGnmrhPJWprLWQPSRXWz9NjASEBEF
f+2aketthG8gRaF5TZAau/u3ruNIOL9oNM9UDloUwOP/hl4X+D9jCDpJT8dCoau0
fVz2lKiMXyXg4DuSWbF/aAsdadBxezhFmR1iUeJWNohA9JJEz9xlJTL1AoGAPDj5
0sJxlYaaaqaAl+aRXprzv0YuN0HDG3Lp0o8Kz6Iiy5wqNpHCoQBMKZG7i3ohAOFp
Da0qooo8JToDrCzPCtdznzCgOkcKDX+4Idl0l6/Pl5dPwDJQqbynJuVtsbW6PJHe
VAozK9pDBRx6kCozop5MER/2h9eXwg+c0G8Ao/ECgYA6uVkHDtzNud+oeorLaPSf
aDnj4y4PT9cgI2JKnt9v2ZhSRKdGxAcnOof7cZ4QfVvGT0XQXQ92Hk3h99I4W0Uh
u4K5SonY0kUGo7DjE9PdfhbghZuLPafivLyiDlcC/cX8cdu6E452EGpVHy15ueYe
bsXx2W1sLcxwWKZ6IhE6pw==
-----END PRIVATE KEY-----
''';

import 'dart:io';
import 'dart:typed_data';

import 'rust_backend.dart';

/// A rustls-backed security context (custom implementation).
///
/// This class mirrors the intent of `dart:io` [SecurityContext], but is
/// independent from the SDK private TLS stack.
class RustSecurityContext {
  RustSecurityContext({bool withTrustedRoots = false})
      : _backend = RustIoBackend.instance,
        _contextId = RustIoBackend.instance.createSecurityContext() {
    if (withTrustedRoots) {
      // Phase 1: trust roots are caller-provided via setTrustedCertificates*.
    }
  }

  final RustIoBackend _backend;
  final int _contextId;

  bool _disposed = false;

  int get nativeHandle {
    if (_disposed) {
      throw StateError('RustSecurityContext is disposed');
    }
    return _contextId;
  }

  void setTrustedCertificates(String file, {String? password}) {
    _verifyPassword(password);
    setTrustedCertificatesBytes(File(file).readAsBytesSync(),
        password: password);
  }

  void setTrustedCertificatesBytes(List<int> certBytes, {String? password}) {
    _verifyOpen();
    _verifyPassword(password);
    _backend.setTrustedCertsPem(_contextId, Uint8List.fromList(certBytes));
  }

  void useCertificateChain(String file, {String? password}) {
    _verifyPassword(password);
    useCertificateChainBytes(File(file).readAsBytesSync(), password: password);
  }

  void useCertificateChainBytes(List<int> chainBytes, {String? password}) {
    _verifyOpen();
    _verifyPassword(password);
    _backend.setCertificateChainPem(_contextId, Uint8List.fromList(chainBytes));
  }

  void usePrivateKey(String file, {String? password}) {
    _verifyPassword(password);
    usePrivateKeyBytes(File(file).readAsBytesSync(), password: password);
  }

  void usePrivateKeyBytes(List<int> keyBytes, {String? password}) {
    _verifyOpen();
    _verifyPassword(password);
    _backend.setPrivateKeyPem(_contextId, Uint8List.fromList(keyBytes));
  }

  void dispose() {
    if (_disposed) {
      return;
    }
    _disposed = true;
    _backend.freeSecurityContext(_contextId);
  }

  void _verifyOpen() {
    if (_disposed) {
      throw StateError('RustSecurityContext is disposed');
    }
  }

  void _verifyPassword(String? password) {
    // rustls-pemfile does not consume password here; encrypted PEM will fail
    // during native parse if unsupported.
  }
}

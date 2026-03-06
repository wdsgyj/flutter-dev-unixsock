import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'rust_backend.dart';
import 'rust_security_context.dart';

/// InternetAddress implementation used by rust-backed sockets.
class RustInternetAddress implements InternetAddress {
  RustInternetAddress(this._address, this._type)
      : _rawAddress = Uint8List.fromList(utf8.encode(_address));

  final String _address;
  final InternetAddressType _type;
  final Uint8List _rawAddress;

  @override
  String get address => _address;

  @override
  String get host => _address;

  @override
  bool get isLinkLocal => false;

  @override
  bool get isLoopback => false;

  @override
  bool get isMulticast => false;

  @override
  Uint8List get rawAddress => Uint8List.fromList(_rawAddress);

  @override
  InternetAddressType get type => _type;

  @override
  Future<InternetAddress> reverse() async => this;

  @override
  String toString() => _address;
}

/// Socket implementation backed by Rust tokio runtime.
class RustSocket extends Stream<Uint8List> implements Socket {
  RustSocket._(
    this._backend,
    this._socketId, {
    required InternetAddress address,
    required InternetAddress remoteAddress,
    required this.port,
    required this.remotePort,
  })  : _address = address,
        _remoteAddress = remoteAddress {
    _backend.registerSocketDispatch(
      _socketId,
      onData: _onData,
      onClosed: _onClosed,
      onError: _onError,
    );
  }

  final RustIoBackend _backend;
  final int _socketId;

  final InternetAddress _address;
  final InternetAddress _remoteAddress;
  final StreamController<Uint8List> _streamController =
      StreamController<Uint8List>(sync: true);
  final Completer<void> _doneCompleter = Completer<void>();
  final List<Completer<void>> _flushWaiters = <Completer<void>>[];
  final Queue<Future<void>> _pendingWrites = Queue<Future<void>>();

  bool _closing = false;
  bool _destroyed = false;

  @override
  final int port;

  @override
  final int remotePort;

  @override
  Encoding encoding = utf8;

  /// `Socket.connect` compatible entry.
  static Future<RustSocket> connect(
    dynamic host,
    int port, {
    dynamic sourceAddress,
    int sourcePort = 0,
    Duration? timeout,
  }) async {
    if (_isUnixAddress(host, port)) {
      if (sourceAddress != null || sourcePort != 0) {
        throw ArgumentError(
            'sourceAddress/sourcePort are unsupported for unix sockets.');
      }
      final String path = _extractUnixPath(host);
      return connectUnix(path, timeout: timeout);
    }

    // The current rust backend does not expose bind-before-connect yet.

    final String address = _extractHost(host);
    return connectTcp(address, port, timeout: timeout);
  }

  static Future<RustSocket> connectTcp(
    String host,
    int port, {
    Duration? timeout,
  }) async {
    final RustIoBackend backend = RustIoBackend.instance;
    final int socketId = await backend.connectTcp(host, port, timeout: timeout);
    return RustSocket._(
      backend,
      socketId,
      address: _defaultLocalAddress(host),
      remoteAddress: _remoteAddressForHost(host),
      port: 0,
      remotePort: port,
    );
  }

  static Future<RustSocket> connectUnix(
    String path, {
    Duration? timeout,
  }) async {
    final RustIoBackend backend = RustIoBackend.instance;
    final int socketId = await backend.connectUnix(path, timeout: timeout);
    return RustSocket._(
      backend,
      socketId,
      address: RustInternetAddress('', InternetAddressType.unix),
      remoteAddress: RustInternetAddress(path, InternetAddressType.unix),
      port: 0,
      remotePort: 0,
    );
  }

  factory RustSocket._accepted(
    RustIoBackend backend,
    int socketId, {
    required InternetAddress address,
    required InternetAddress remoteAddress,
    required int port,
    required int remotePort,
  }) {
    return RustSocket._(
      backend,
      socketId,
      address: address,
      remoteAddress: remoteAddress,
      port: port,
      remotePort: remotePort,
    );
  }

  void _onData(Uint8List data) {
    if (_destroyed || _streamController.isClosed) {
      return;
    }
    _streamController.add(data);
  }

  void _onClosed() {
    _finishClose();
  }

  void _onError(Object error, StackTrace stackTrace) {
    if (_destroyed) {
      return;
    }
    if (!_streamController.isClosed) {
      _streamController.addError(error, stackTrace);
    }
    _failFlushWaiters(error, stackTrace);
    _finishClose();
  }

  @override
  InternetAddress get address {
    if (_destroyed) {
      throw SocketException('Socket is closed');
    }
    return _address;
  }

  @override
  InternetAddress get remoteAddress {
    if (_destroyed) {
      throw SocketException('Socket is closed');
    }
    return _remoteAddress;
  }

  @override
  bool setOption(SocketOption option, bool enabled) {
    // Phase 1: socket options are not plumbed to rust backend yet.
    return false;
  }

  @override
  Uint8List getRawOption(RawSocketOption option) {
    final _ = option;
    return Uint8List(0);
  }

  @override
  void setRawOption(RawSocketOption option) {
    final _ = option;
  }

  @override
  void add(List<int> data) {
    if (data.isEmpty) {
      return;
    }
    if (_destroyed || _closing) {
      throw StateError('Cannot write to a closed RustSocket');
    }

    final Uint8List payload = Uint8List.fromList(data);
    late final Future<void> writeFuture;
    writeFuture = _backend.writeSocket(_socketId, payload).then((_) {
      _pendingWrites.remove(writeFuture);
      _completeFlushIfIdle();
    }).catchError((Object error, StackTrace stackTrace) {
      _pendingWrites.remove(writeFuture);
      _failFlushWaiters(error, stackTrace);
      _onError(error, stackTrace);
    });

    _pendingWrites.add(writeFuture);
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final List<int> chunk in stream) {
      add(chunk);
    }
    await flush();
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {
    if (_destroyed || _streamController.isClosed) {
      return;
    }
    _streamController.addError(error, stackTrace);
  }

  @override
  Future<void> flush() {
    if (_destroyed) {
      return Future<void>.error(StateError('Socket is closed'));
    }
    if (_pendingWrites.isEmpty) {
      return Future<void>.value();
    }
    final Completer<void> completer = Completer<void>();
    _flushWaiters.add(completer);
    return completer.future;
  }

  void _completeFlushIfIdle() {
    if (_pendingWrites.isNotEmpty) {
      return;
    }
    for (final Completer<void> completer in _flushWaiters) {
      if (!completer.isCompleted) {
        completer.complete();
      }
    }
    _flushWaiters.clear();
  }

  void _failFlushWaiters(Object error, [StackTrace? stackTrace]) {
    for (final Completer<void> completer in _flushWaiters) {
      if (!completer.isCompleted) {
        completer.completeError(error, stackTrace);
      }
    }
    _flushWaiters.clear();
  }

  @override
  void write(Object? object) {
    add(encoding.encode(object?.toString() ?? 'null'));
  }

  @override
  void writeAll(Iterable<dynamic> objects, [String separator = '']) {
    final Iterator<dynamic> iterator = objects.iterator;
    if (!iterator.moveNext()) {
      return;
    }
    write(iterator.current);
    while (iterator.moveNext()) {
      if (separator.isNotEmpty) {
        write(separator);
      }
      write(iterator.current);
    }
  }

  @override
  void writeCharCode(int charCode) {
    write(String.fromCharCode(charCode));
  }

  @override
  void writeln([Object? object = '']) {
    write(object);
    add(const <int>[0x0A]);
  }

  @override
  Future close() async {
    if (_destroyed) {
      return done;
    }
    _closing = true;
    await flush();
    try {
      await _backend.closeSocket(_socketId);
    } catch (_) {
      // If already closed remotely, this can race.
    }
    return done;
  }

  @override
  Future get done => _doneCompleter.future;

  @override
  void destroy() {
    if (_destroyed) {
      return;
    }
    _destroyed = true;
    _backend.unregisterSocketDispatch(_socketId);
    unawaited(_backend.closeSocket(_socketId).catchError((Object _) {}));
    _finishClose();
  }

  void _finishClose() {
    if (_doneCompleter.isCompleted) {
      return;
    }
    _destroyed = true;
    _backend.unregisterSocketDispatch(_socketId);
    if (!_streamController.isClosed) {
      _streamController.close();
    }
    _completeFlushIfIdle();
    _doneCompleter.complete();
  }

  @override
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List data)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    return _streamController.stream.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }
}

/// ServerSocket implementation backed by Rust tokio runtime.
class RustServerSocket extends Stream<Socket> implements ServerSocket {
  RustServerSocket._(
    this._backend,
    this._serverId, {
    required this.address,
    required this.port,
    this.path,
  }) {
    _backend.registerServerAcceptHandler(_serverId, _onAccept);
  }

  final RustIoBackend _backend;
  final int _serverId;
  @override
  final InternetAddress address;
  @override
  final int port;

  final String? path;

  final StreamController<Socket> _streamController =
      StreamController<Socket>(sync: true);
  bool _closed = false;

  /// `ServerSocket.bind` compatible entry.
  static Future<RustServerSocket> bind(
    dynamic address,
    int port, {
    int backlog = 0,
    bool v6Only = false,
    bool shared = false,
    bool removeExisting = true,
  }) async {
    if (_isUnixAddress(address, port)) {
      return bindUnix(_extractUnixPath(address),
          removeExisting: removeExisting);
    }
    return bindTcp(_extractHost(address), port);
  }

  static Future<RustServerSocket> bindTcp(String host, int port) async {
    final RustIoBackend backend = RustIoBackend.instance;
    final ({int serverId, int port}) result = await backend.bindTcp(host, port);
    return RustServerSocket._(
      backend,
      result.serverId,
      address: _remoteAddressForHost(host),
      port: result.port,
    );
  }

  static Future<RustServerSocket> bindUnix(
    String path, {
    bool removeExisting = true,
  }) async {
    final RustIoBackend backend = RustIoBackend.instance;
    final int serverId =
        await backend.bindUnix(path, removeExisting: removeExisting);
    return RustServerSocket._(
      backend,
      serverId,
      address: RustInternetAddress(path, InternetAddressType.unix),
      port: 0,
      path: path,
    );
  }

  void _onAccept(int socketId) {
    if (_closed || _streamController.isClosed) {
      return;
    }
    final RustSocket socket = RustSocket._accepted(
      _backend,
      socketId,
      address: address,
      remoteAddress: address,
      port: port,
      remotePort: 0,
    );
    _streamController.add(socket);
  }

  @override
  Future<ServerSocket> close() async {
    if (_closed) {
      return this;
    }
    _closed = true;
    _backend.unregisterServerAcceptHandler(_serverId);
    try {
      await _backend.closeServer(_serverId);
    } catch (_) {
      // Ignore close race.
    }
    await _streamController.close();
    return this;
  }

  @override
  StreamSubscription<Socket> listen(
    void Function(Socket data)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    return _streamController.stream.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }
}

/// SecureSocket implementation backed by Rust tokio + rustls.
class RustSecureSocket extends Stream<Uint8List> implements SecureSocket {
  RustSecureSocket._(this._inner);

  final RustSocket _inner;

  @override
  final X509Certificate? peerCertificate = null;

  @override
  final String? selectedProtocol = null;

  /// `SecureSocket.connect` compatible entry for TCP/Unix.
  static Future<RustSecureSocket> connect(
    dynamic host,
    int port, {
    RustSecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    Duration? timeout,
    String tlsServerName = 'localhost',
  }) async {
    if (_isUnixAddress(host, port)) {
      final String path = _extractUnixPath(host);
      return connectUnix(
        path,
        serverName: tlsServerName,
        context: context,
        onBadCertificate: onBadCertificate,
        timeout: timeout,
      );
    }

    final String address = _extractHost(host);
    return connectTcp(
      address,
      port,
      context: context,
      onBadCertificate: onBadCertificate,
      timeout: timeout,
    );
  }

  static Future<RustSecureSocket> connectTcp(
    String host,
    int port, {
    RustSecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    Duration? timeout,
  }) async {
    final RustIoBackend backend = RustIoBackend.instance;
    final int socketId = await backend.connectTlsTcp(
      host,
      port,
      securityContextId: context?.nativeHandle ?? 0,
      onBadCertificate: onBadCertificate,
      timeout: timeout,
    );
    final RustSocket inner = RustSocket._accepted(
      backend,
      socketId,
      address: _defaultLocalAddress(host),
      remoteAddress: _remoteAddressForHost(host),
      port: 0,
      remotePort: port,
    );
    return RustSecureSocket._(inner);
  }

  static Future<RustSecureSocket> connectUnix(
    String path, {
    required String serverName,
    RustSecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    Duration? timeout,
  }) async {
    final RustIoBackend backend = RustIoBackend.instance;
    final int socketId = await backend.connectTlsUnix(
      path,
      serverName: serverName,
      securityContextId: context?.nativeHandle ?? 0,
      onBadCertificate: onBadCertificate,
      timeout: timeout,
    );
    final RustSocket inner = RustSocket._accepted(
      backend,
      socketId,
      address: RustInternetAddress('', InternetAddressType.unix),
      remoteAddress: RustInternetAddress(path, InternetAddressType.unix),
      port: 0,
      remotePort: 0,
    );
    return RustSecureSocket._(inner);
  }

  static Future<ConnectionTask<RustSecureSocket>> startConnect(
    dynamic host,
    int port, {
    RustSecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    String tlsServerName = 'localhost',
  }) async {
    bool cancelled = false;
    RustSecureSocket? connected;
    final Completer<RustSecureSocket> completer = Completer<RustSecureSocket>();

    void completeCancelled() {
      if (!completer.isCompleted) {
        completer.completeError(
          SocketException('Connection attempt was cancelled'),
        );
      }
    }

    unawaited(() async {
      try {
        final RustSecureSocket socket = await connect(
          host,
          port,
          context: context,
          onBadCertificate: onBadCertificate,
          tlsServerName: tlsServerName,
        );
        if (cancelled) {
          socket.destroy();
          completeCancelled();
          return;
        }
        connected = socket;
        if (!completer.isCompleted) {
          completer.complete(socket);
        }
      } catch (error, stackTrace) {
        if (!completer.isCompleted) {
          completer.completeError(error, stackTrace);
        }
      }
    }());

    return ConnectionTask.fromSocket(
      completer.future,
      () {
        cancelled = true;
        connected?.destroy();
        completeCancelled();
      },
    );
  }

  static Future<RustSecureSocket> secure(
    Socket socket, {
    host,
    RustSecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
  }) async {
    if (socket is RustSecureSocket) {
      return socket;
    }
    if (socket is! RustSocket) {
      throw ArgumentError.value(
        socket,
        'socket',
        'RustSecureSocket.secure requires a RustSocket',
      );
    }

    final String serverName = _resolveServerNameForSecure(socket, host);
    await socket._backend.secureSocketTlsClient(
      socket._socketId,
      serverName: serverName,
      securityContextId: context?.nativeHandle ?? 0,
      onBadCertificate: onBadCertificate,
    );
    return RustSecureSocket._(socket);
  }

  static Future<RustSecureSocket> secureServer(
    Socket socket,
    RustSecurityContext? context, {
    List<int>? bufferedData,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  }) async {
    if (socket is RustSecureSocket) {
      return socket;
    }
    if (socket is! RustSocket) {
      throw ArgumentError.value(
        socket,
        'socket',
        'RustSecureSocket.secureServer requires a RustSocket',
      );
    }
    if (context == null) {
      throw ArgumentError.notNull('context');
    }

    await socket._backend.secureSocketTlsServer(
      socket._socketId,
      securityContextId: context.nativeHandle,
      requestClientCertificate: requestClientCertificate,
      requireClientCertificate: requireClientCertificate,
    );

    final RustSecureSocket secureSocket = RustSecureSocket._(socket);
    if (bufferedData != null && bufferedData.isNotEmpty) {
      scheduleMicrotask(() {
        socket._onData(Uint8List.fromList(bufferedData));
      });
    }
    return secureSocket;
  }

  @override
  void renegotiate({
    bool useSessionCache = true,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  }) {
    // rustls does not support renegotiation; keep API parity.
  }

  @override
  Encoding get encoding => _inner.encoding;

  @override
  set encoding(Encoding value) => _inner.encoding = value;

  @override
  int get port => _inner.port;

  @override
  int get remotePort => _inner.remotePort;

  @override
  InternetAddress get address => _inner.address;

  @override
  InternetAddress get remoteAddress => _inner.remoteAddress;

  @override
  bool setOption(SocketOption option, bool enabled) =>
      _inner.setOption(option, enabled);

  @override
  Uint8List getRawOption(RawSocketOption option) => _inner.getRawOption(option);

  @override
  void setRawOption(RawSocketOption option) => _inner.setRawOption(option);

  @override
  void add(List<int> data) => _inner.add(data);

  @override
  Future<void> addStream(Stream<List<int>> stream) => _inner.addStream(stream);

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      _inner.addError(error, stackTrace);

  @override
  Future<void> flush() => _inner.flush();

  @override
  void write(Object? object) => _inner.write(object);

  @override
  void writeAll(Iterable<dynamic> objects, [String separator = '']) =>
      _inner.writeAll(objects, separator);

  @override
  void writeCharCode(int charCode) => _inner.writeCharCode(charCode);

  @override
  void writeln([Object? object = '']) => _inner.writeln(object);

  @override
  Future close() => _inner.close();

  @override
  Future get done => _inner.done;

  @override
  void destroy() => _inner.destroy();

  @override
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List data)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    return _inner.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }
}

bool _isUnixAddress(dynamic hostOrAddress, int port) {
  if (hostOrAddress is InternetAddress &&
      hostOrAddress.type == InternetAddressType.unix) {
    return true;
  }
  if (hostOrAddress is RustInternetAddress &&
      hostOrAddress.type == InternetAddressType.unix) {
    return true;
  }
  if (hostOrAddress is String && port == 0) {
    return hostOrAddress.startsWith('/') || hostOrAddress.startsWith(r'\\');
  }
  return false;
}

String _extractHost(dynamic hostOrAddress) {
  if (hostOrAddress is InternetAddress) {
    return hostOrAddress.address;
  }
  if (hostOrAddress is RustInternetAddress) {
    return hostOrAddress.address;
  }
  if (hostOrAddress is String) {
    return hostOrAddress;
  }
  throw ArgumentError.value(hostOrAddress, 'hostOrAddress', 'Invalid host');
}

String _extractUnixPath(dynamic hostOrAddress) {
  if (hostOrAddress is InternetAddress &&
      hostOrAddress.type == InternetAddressType.unix) {
    return hostOrAddress.address;
  }
  if (hostOrAddress is RustInternetAddress &&
      hostOrAddress.type == InternetAddressType.unix) {
    return hostOrAddress.address;
  }
  if (hostOrAddress is String) {
    return hostOrAddress;
  }
  throw ArgumentError.value(
      hostOrAddress, 'hostOrAddress', 'Invalid unix path');
}

String _resolveServerNameForSecure(RustSocket socket, dynamic host) {
  if (host != null) {
    final String extracted = _extractHost(host);
    if (extracted.isNotEmpty) {
      return extracted;
    }
  }

  final InternetAddress remote = socket.remoteAddress;
  if (remote.type == InternetAddressType.unix) {
    return 'localhost';
  }
  if (remote.address.isNotEmpty) {
    return remote.address;
  }
  return 'localhost';
}

InternetAddress _remoteAddressForHost(String host) {
  final InternetAddress? parsed = InternetAddress.tryParse(host);
  if (parsed != null) {
    return parsed;
  }
  return RustInternetAddress(host, InternetAddressType.any);
}

InternetAddress _defaultLocalAddress(String host) {
  final InternetAddress? parsed = InternetAddress.tryParse(host);
  if (parsed != null && parsed.type == InternetAddressType.IPv6) {
    return InternetAddress.anyIPv6;
  }
  return InternetAddress.anyIPv4;
}

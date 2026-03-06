import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

const int _afUnix = 1;
const int _sockStream = 1;
const int _sockNonBlockLinux = 0x0800;

const int _pollIn = 0x0001;
const int _pollOut = 0x0004;
const int _pollErr = 0x0008;
const int _pollHup = 0x0010;
const int _pollNVal = 0x0020;

const int _solSocket = 1;
const int _soError = 4;
const int _shutWrite = 1;

const int _enoent = 2;
const int _eintr = 4;
const int _einval = 22;
const int _enosys = 38;

final int _eWouldBlock = (Platform.isMacOS || Platform.isIOS) ? 35 : 11;
final int _eInProgress = (Platform.isMacOS || Platform.isIOS) ? 36 : 115;
final int _sunPathMax = (Platform.isMacOS || Platform.isIOS) ? 104 : 108;

const Duration _defaultPollInterval = Duration(milliseconds: 8);
const int _readChunk = 8192;
const int _writeChunk = 8192;

/// A Unix domain address implementation for [Socket]/[ServerSocket] subtypes.
class UnixInternetAddress implements InternetAddress {
  UnixInternetAddress(this.path)
      : _rawAddress = Uint8List.fromList(utf8.encode(path));

  final String path;
  final Uint8List _rawAddress;

  @override
  String get address => path;

  @override
  String get host => path;

  @override
  bool get isLinkLocal => false;

  @override
  bool get isLoopback => false;

  @override
  bool get isMulticast => false;

  @override
  Uint8List get rawAddress => Uint8List.fromList(_rawAddress);

  @override
  InternetAddressType get type => InternetAddressType.unix;

  @override
  Future<InternetAddress> reverse() async => this;

  @override
  String toString() => path;
}

/// A non-blocking Unix domain [Socket] built with libc primitives through FFI.
class UnixSocket extends Stream<Uint8List> implements Socket {
  UnixSocket._(
    this._fd, {
    required String localPath,
    required String remotePath,
    required bool connecting,
    this.pollInterval = _defaultPollInterval,
  })  : _address = UnixInternetAddress(localPath),
        _remoteAddress = UnixInternetAddress(remotePath),
        _connecting = connecting,
        _streamController = StreamController<Uint8List>(sync: true);

  final int _fd;
  final UnixInternetAddress _address;
  final UnixInternetAddress _remoteAddress;
  final StreamController<Uint8List> _streamController;
  final Queue<_PendingWrite> _writeQueue = Queue<_PendingWrite>();
  final List<Completer<void>> _flushWaiters = <Completer<void>>[];
  final Completer<void> _doneCompleter = Completer<void>();

  final Duration pollInterval;

  bool _connecting;
  bool _destroyed = false;
  bool _inputClosed = false;
  bool _writeClosing = false;
  bool _writeShutdown = false;

  int? _reactorRegistrationId;
  Completer<UnixSocket>? _connectCompleter;
  Timer? _connectTimeoutTimer;

  @override
  Encoding encoding = utf8;

  /// Connects to a Unix domain socket path.
  static Future<UnixSocket> connect(
    String path, {
    Duration? timeout,
    Duration pollInterval = _defaultPollInterval,
  }) async {
    _ensureSupportedPlatform();
    await _pollReactor.ensureRunning();
    final int fd = _libc.socket(_afUnix, _socketTypeForPlatform(), 0);
    if (fd < 0) {
      throw _socketException('socket() failed', _libc.errno);
    }

    try {
      _ensureNonBlockingSocket(fd);

      final _SockAddr addr = _encodeSockAddr(path);
      try {
        final int result = _libc.connect(fd, addr.pointer, addr.length);
        if (result == 0) {
          final socket = UnixSocket._(
            fd,
            localPath: '',
            remotePath: path,
            connecting: false,
            pollInterval: pollInterval,
          );
          await socket._attachToReactor();
          return socket;
        }

        final int error = _libc.errno;
        if (error != _eInProgress && !_isWouldBlock(error)) {
          throw _socketException('connect() failed for "$path"', error);
        }

        final socket = UnixSocket._(
          fd,
          localPath: '',
          remotePath: path,
          connecting: true,
          pollInterval: pollInterval,
        );
        await socket._attachToReactor();
        return socket._waitForConnect(timeout);
      } finally {
        addr.free();
      }
    } catch (_) {
      _closeFd(fd);
      await _pollReactor.shutdownIfIdle();
      rethrow;
    }
  }

  /// Creates a [UnixSocket] from an accepted server connection.
  factory UnixSocket._accepted(
    int fd, {
    required String localPath,
  }) {
    final socket = UnixSocket._(
      fd,
      localPath: localPath,
      remotePath: localPath,
      connecting: false,
      pollInterval: _defaultPollInterval,
    );
    socket._attachToReactorSync();
    return socket;
  }

  Future<UnixSocket> _waitForConnect(Duration? timeout) {
    if (!_connecting) {
      return Future<UnixSocket>.value(this);
    }
    _connectCompleter ??= Completer<UnixSocket>();
    if (timeout != null) {
      _connectTimeoutTimer?.cancel();
      _connectTimeoutTimer = Timer(timeout, () {
        if (_connectCompleter?.isCompleted == false) {
          final error = SocketException(
            'UnixSocket.connect timeout after ${timeout.inMilliseconds} ms',
          );
          _connectCompleter!.completeError(error);
          destroy();
        }
      });
    }
    return _connectCompleter!.future;
  }

  int get _reactorEvents {
    int events = _pollIn;
    if (_connecting || _writeQueue.isNotEmpty) {
      events |= _pollOut;
    }
    return events;
  }

  Future<void> _attachToReactor() async {
    _reactorRegistrationId = await _pollReactor.register(
      fd: _fd,
      events: _reactorEvents,
      onEvent: _onReactorEvent,
    );
  }

  void _attachToReactorSync() {
    _reactorRegistrationId = _pollReactor.registerSync(
      fd: _fd,
      events: _reactorEvents,
      onEvent: _onReactorEvent,
    );
  }

  void _detachFromReactor() {
    final int? id = _reactorRegistrationId;
    _reactorRegistrationId = null;
    if (id != null) {
      unawaited(_pollReactor.unregister(id));
    }
  }

  void _updateReactorInterest() {
    final int? id = _reactorRegistrationId;
    if (id != null) {
      _pollReactor.updateInterest(id, _reactorEvents);
    }
  }

  void _onReactorEvent(int revents) {
    if (_destroyed) {
      return;
    }

    if (_connecting &&
        (revents & (_pollOut | _pollErr | _pollHup | _pollNVal)) != 0) {
      _finishConnect();
    }

    if (_destroyed || _connecting) {
      return;
    }

    if ((revents & (_pollErr | _pollNVal)) != 0) {
      _closeWithError(
          _socketException('socket error event', _readSocketError()));
      return;
    }

    if ((revents & _pollIn) != 0) {
      _readAvailable();
    }

    if (_destroyed) {
      return;
    }

    if (_writeQueue.isNotEmpty && (revents & _pollOut) != 0) {
      _flushWriteQueue();
    }

    _tryShutdownWrite();
    _maybeFinishIfHalfClosed();
  }

  void _finishConnect() {
    final int soError = _readSocketError();
    if (soError == 0) {
      _connecting = false;
      _updateReactorInterest();
      _connectTimeoutTimer?.cancel();
      if (_connectCompleter?.isCompleted == false) {
        _connectCompleter!.complete(this);
      }
      return;
    }

    final error = _socketException('connect() failed', soError);
    _connectTimeoutTimer?.cancel();
    if (_connectCompleter?.isCompleted == false) {
      _connectCompleter!.completeError(error);
    }
    _closeWithError(error);
  }

  int _readSocketError() {
    final value = calloc<Int32>();
    final length = calloc<Uint32>();
    try {
      length.value = sizeOf<Int32>();
      final int result = _libc.getsockopt(
        _fd,
        _solSocket,
        _soError,
        value.cast<Void>(),
        length,
      );
      if (result != 0) {
        return _libc.errno;
      }
      return value.value;
    } finally {
      calloc.free(value);
      calloc.free(length);
    }
  }

  void _readAvailable() {
    final buffer = calloc<Uint8>(_readChunk);
    try {
      while (!_destroyed) {
        final int read = _libc.recv(_fd, buffer.cast<Void>(), _readChunk, 0);
        if (read > 0) {
          final data = Uint8List.fromList(buffer.asTypedList(read));
          if (!_streamController.isClosed) {
            _streamController.add(data);
          }
          continue;
        }

        if (read == 0) {
          _inputClosed = true;
          _streamController.close();
          return;
        }

        final int error = _libc.errno;
        if (_isWouldBlock(error)) {
          return;
        }
        if (error == _eintr) {
          continue;
        }
        _closeWithError(_socketException('recv() failed', error));
        return;
      }
    } finally {
      calloc.free(buffer);
    }
  }

  void _flushWriteQueue() {
    while (_writeQueue.isNotEmpty && !_destroyed) {
      final pending = _writeQueue.first;
      final int remaining = pending.data.length - pending.offset;
      final int chunk = math.min(remaining, _writeChunk);
      final pointer = calloc<Uint8>(chunk);
      try {
        pointer.asTypedList(chunk).setAll(
              0,
              pending.data.sublist(pending.offset, pending.offset + chunk),
            );

        final int sent = _libc.send(_fd, pointer.cast<Void>(), chunk, 0);

        if (sent > 0) {
          pending.offset += sent;
          if (pending.offset >= pending.data.length) {
            _writeQueue.removeFirst();
          }
          continue;
        }

        if (sent == 0) {
          return;
        }

        final int error = _libc.errno;
        if (_isWouldBlock(error)) {
          return;
        }
        if (error == _eintr) {
          continue;
        }

        _closeWithError(_socketException('send() failed', error));
        return;
      } finally {
        calloc.free(pointer);
      }
    }

    if (_writeQueue.isEmpty) {
      _updateReactorInterest();
      for (final completer in _flushWaiters) {
        if (!completer.isCompleted) {
          completer.complete();
        }
      }
      _flushWaiters.clear();
    }
  }

  void _tryShutdownWrite() {
    if (_writeClosing &&
        !_writeShutdown &&
        _writeQueue.isEmpty &&
        !_destroyed) {
      final int result = _libc.shutdown(_fd, _shutWrite);
      if (result != 0) {
        final int error = _libc.errno;
        if (error != _enoent) {
          _closeWithError(_socketException('shutdown() failed', error));
          return;
        }
      }
      _writeShutdown = true;
      _completeDone();
    }
  }

  void _maybeFinishIfHalfClosed() {
    if (_inputClosed && _writeShutdown) {
      _finalClose();
    }
  }

  void _closeWithError(Object error, [StackTrace? stackTrace]) {
    if (!_streamController.isClosed) {
      _streamController.addError(error, stackTrace);
      _streamController.close();
    }
    _failFlushWaiters(error, stackTrace);
    _finalClose();
  }

  void _finalClose() {
    if (_destroyed) {
      return;
    }
    _destroyed = true;
    _detachFromReactor();
    _closeFd(_fd);
    _connectTimeoutTimer?.cancel();
    if (_connectCompleter != null && !_connectCompleter!.isCompleted) {
      _connectCompleter!.completeError(
        StateError('UnixSocket closed before connected'),
      );
    }
    if (!_streamController.isClosed) {
      _streamController.close();
    }
    _failFlushWaiters(StateError('Socket is closed'));
    _completeDone();
  }

  void _completeDone() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
  }

  void _failFlushWaiters(Object error, [StackTrace? stackTrace]) {
    for (final completer in _flushWaiters) {
      if (!completer.isCompleted) {
        completer.completeError(error, stackTrace);
      }
    }
    _flushWaiters.clear();
  }

  bool _ensureOpenForWrite() {
    if (_destroyed || _writeClosing) {
      return false;
    }
    return true;
  }

  @override
  int get port => 0;

  @override
  int get remotePort => 0;

  @override
  InternetAddress get address {
    if (_destroyed) {
      throw _socketException('Socket is closed', _enoent);
    }
    return _address;
  }

  @override
  InternetAddress get remoteAddress {
    if (_destroyed) {
      throw _socketException('Socket is closed', _enoent);
    }
    return _remoteAddress;
  }

  @override
  bool setOption(SocketOption option, bool enabled) {
    if (_destroyed) {
      throw _socketException('Socket is closed', _enoent);
    }
    if (identical(option, SocketOption.tcpNoDelay)) {
      // Unix domain sockets are not TCP sockets.
      return false;
    }
    return false;
  }

  @override
  Uint8List getRawOption(RawSocketOption option) {
    if (_destroyed) {
      throw _socketException('Socket is closed', _enoent);
    }
    final int requestedLength = option.value.isEmpty ? 4 : option.value.length;
    final value = calloc<Uint8>(requestedLength);
    final length = calloc<Uint32>();
    try {
      length.value = requestedLength;
      final int result = _libc.getsockopt(
        _fd,
        option.level,
        option.option,
        value.cast<Void>(),
        length,
      );
      if (result != 0) {
        throw _socketException('getsockopt() failed', _libc.errno);
      }
      return Uint8List.fromList(value.asTypedList(length.value));
    } finally {
      calloc.free(value);
      calloc.free(length);
    }
  }

  @override
  void setRawOption(RawSocketOption option) {
    if (_destroyed) {
      throw _socketException('Socket is closed', _enoent);
    }
    final value = calloc<Uint8>(math.max(option.value.length, 1));
    try {
      if (option.value.isNotEmpty) {
        value.asTypedList(option.value.length).setAll(0, option.value);
      }
      final int result = _libc.setsockopt(
        _fd,
        option.level,
        option.option,
        value.cast<Void>(),
        option.value.length,
      );
      if (result != 0) {
        throw _socketException('setsockopt() failed', _libc.errno);
      }
    } finally {
      calloc.free(value);
    }
  }

  @override
  void add(List<int> data) {
    if (data.isEmpty) {
      return;
    }
    if (!_ensureOpenForWrite()) {
      throw StateError('Cannot write to a closed UnixSocket');
    }
    _writeQueue.add(_PendingWrite(Uint8List.fromList(data)));
    _updateReactorInterest();
  }

  @override
  void write(Object? object) {
    add(encoding.encode(object?.toString() ?? 'null'));
  }

  @override
  void writeln([Object? object = '']) {
    write(object);
    add(const <int>[0x0A]);
  }

  @override
  void writeAll(Iterable<dynamic> objects, [String separator = '']) {
    final iterator = objects.iterator;
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
  Future<void> flush() {
    if (_destroyed) {
      return Future<void>.error(StateError('Socket is closed'));
    }
    if (_writeQueue.isEmpty) {
      return Future<void>.value();
    }
    final completer = Completer<void>();
    _flushWaiters.add(completer);
    return completer.future;
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
    throw UnsupportedError('Socket.addError is not supported.');
  }

  @override
  Future close() {
    if (_destroyed) {
      return done;
    }
    _writeClosing = true;
    _tryShutdownWrite();
    _maybeFinishIfHalfClosed();
    return done;
  }

  @override
  Future get done => _doneCompleter.future;

  @override
  void destroy() {
    _finalClose();
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

/// A non-blocking Unix domain [ServerSocket] built with libc primitives.
class UnixServerSocket extends Stream<Socket> implements ServerSocket {
  UnixServerSocket._(
    this._fd,
    this.path, {
    required this.deletePathOnClose,
    this.pollInterval = _defaultPollInterval,
  }) : _address = UnixInternetAddress(path);

  final int _fd;
  final UnixInternetAddress _address;

  /// Filesystem path for this Unix domain server socket.
  final String path;

  /// Poll interval for accept loop.
  final Duration pollInterval;

  /// Whether socket path file should be deleted when [close] is called.
  final bool deletePathOnClose;

  final StreamController<Socket> _streamController = StreamController<Socket>(
    sync: true,
  );

  int? _reactorRegistrationId;
  bool _closed = false;

  /// Binds a Unix domain server socket.
  static Future<UnixServerSocket> bind(
    String path, {
    int backlog = 128,
    bool removeExisting = true,
    bool deletePathOnClose = true,
    Duration pollInterval = _defaultPollInterval,
  }) async {
    _ensureSupportedPlatform();
    await _pollReactor.ensureRunning();

    if (removeExisting) {
      _unlinkIgnoringMissing(path);
    }

    final int fd = _libc.socket(_afUnix, _socketTypeForPlatform(), 0);
    if (fd < 0) {
      throw _socketException('socket() failed', _libc.errno);
    }

    try {
      _ensureNonBlockingSocket(fd);

      final _SockAddr addr = _encodeSockAddr(path);
      try {
        final int bindResult = _libc.bind(fd, addr.pointer, addr.length);
        if (bindResult != 0) {
          throw _socketException('bind() failed for "$path"', _libc.errno);
        }
      } finally {
        addr.free();
      }

      final int listenResult = _libc.listen(fd, backlog);
      if (listenResult != 0) {
        throw _socketException('listen() failed', _libc.errno);
      }

      final server = UnixServerSocket._(
        fd,
        path,
        deletePathOnClose: deletePathOnClose,
        pollInterval: pollInterval,
      );
      await server._attachToReactor();
      return server;
    } catch (_) {
      _closeFd(fd);
      await _pollReactor.shutdownIfIdle();
      rethrow;
    }
  }

  Future<void> _attachToReactor() async {
    _reactorRegistrationId = await _pollReactor.register(
      fd: _fd,
      events: _pollIn,
      onEvent: _onReactorEvent,
    );
  }

  void _detachFromReactor() {
    final int? id = _reactorRegistrationId;
    _reactorRegistrationId = null;
    if (id != null) {
      unawaited(_pollReactor.unregister(id));
    }
  }

  void _onReactorEvent(int revents) {
    if (_closed) {
      return;
    }

    if ((revents & (_pollErr | _pollHup | _pollNVal)) != 0) {
      _streamController.addError(
        _socketException('server socket error event', _readSocketError()),
      );
      return;
    }

    if ((revents & _pollIn) != 0) {
      _acceptReadyClients();
    }
  }

  int _readSocketError() {
    final value = calloc<Int32>();
    final length = calloc<Uint32>();
    try {
      length.value = sizeOf<Int32>();
      final int result = _libc.getsockopt(
        _fd,
        _solSocket,
        _soError,
        value.cast<Void>(),
        length,
      );
      if (result != 0) {
        return _libc.errno;
      }
      return value.value;
    } finally {
      calloc.free(value);
      calloc.free(length);
    }
  }

  void _acceptReadyClients() {
    while (!_closed) {
      final int clientFd;
      try {
        clientFd = _acceptClientFd(_fd);
      } catch (error, stackTrace) {
        _streamController.addError(error, stackTrace);
        return;
      }
      if (clientFd >= 0) {
        try {
          _streamController.add(
            UnixSocket._accepted(
              clientFd,
              localPath: path,
            ),
          );
        } catch (error, stackTrace) {
          _closeFd(clientFd);
          _streamController.addError(error, stackTrace);
        }
        continue;
      }

      final int error = _libc.errno;
      if (_isWouldBlock(error)) {
        return;
      }
      if (error == _eintr) {
        continue;
      }

      _streamController.addError(_socketException('accept() failed', error));
      return;
    }
  }

  @override
  int get port => 0;

  @override
  InternetAddress get address => _address;

  @override
  Future<ServerSocket> close() async {
    if (_closed) {
      return this;
    }
    _closed = true;
    _detachFromReactor();
    _closeFd(_fd);
    if (deletePathOnClose) {
      _unlinkIgnoringMissing(path);
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

class _PendingWrite {
  _PendingWrite(this.data);

  final Uint8List data;
  int offset = 0;
}

class _SockAddr {
  _SockAddr(this.pointer, this.length);

  final Pointer<Uint8> pointer;
  final int length;

  void free() => calloc.free(pointer);
}

_SockAddr _encodeSockAddr(String path) {
  final bytes = utf8.encode(path);
  if (bytes.contains(0)) {
    throw ArgumentError.value(
      path,
      'path',
      'Unix socket path cannot contain NUL bytes',
    );
  }
  if (bytes.length >= _sunPathMax) {
    throw ArgumentError.value(
      path,
      'path',
      'Unix socket path is too long. max=${_sunPathMax - 1}, actual=${bytes.length}',
    );
  }

  final int length = 2 + bytes.length + 1;
  final pointer = calloc<Uint8>(length);

  if (Platform.isMacOS || Platform.isIOS) {
    pointer[0] = length;
    pointer[1] = _afUnix;
  } else {
    pointer[0] = _afUnix;
    pointer[1] = 0;
  }

  final payload = pointer.asTypedList(length);
  payload.setRange(2, 2 + bytes.length, bytes);
  payload[2 + bytes.length] = 0;

  return _SockAddr(pointer, length);
}

void _ensureSupportedPlatform() {
  if (!(Platform.isLinux ||
      Platform.isMacOS ||
      Platform.isAndroid ||
      Platform.isIOS)) {
    throw UnsupportedError(
      'Unix domain sockets are only supported on Android/iOS/macOS/Linux.',
    );
  }
}

bool _isWouldBlock(int error) => error == _eWouldBlock;

bool _useLinuxSocketFlags() => Platform.isLinux || Platform.isAndroid;

int _socketTypeForPlatform() {
  if (_useLinuxSocketFlags()) {
    return _sockStream | _sockNonBlockLinux;
  }
  return _sockStream;
}

void _ensureNonBlockingSocket(int fd) {
  if (_useLinuxSocketFlags()) {
    return;
  }
  final int result = _nativeShim.setNonBlocking(fd, true);
  if (result != 0) {
    throw _socketException('unixsock_set_nonblocking() failed', _libc.errno);
  }
}

int _acceptClientFd(int serverFd) {
  final _Accept4Dart? accept4 = _libc.accept4;
  if (_useLinuxSocketFlags() && accept4 != null) {
    final int fd = accept4(serverFd, nullptr, nullptr, _sockNonBlockLinux);
    if (fd >= 0) {
      return fd;
    }

    final int error = _libc.errno;
    if (error != _enosys && error != _einval) {
      return -1;
    }
  }

  if (_useLinuxSocketFlags()) {
    throw UnsupportedError(
      'accept4 is required on Linux/Android to keep accepted sockets non-blocking '
      'without variadic fcntl/ioctl wrappers.',
    );
  }

  final int fd = _libc.accept(serverFd, nullptr, nullptr);
  if (fd >= 0) {
    _ensureNonBlockingSocket(fd);
  }
  return fd;
}

void _unlinkIgnoringMissing(String path) {
  final nativePath = path.toNativeUtf8();
  try {
    final int result = _libc.unlink(nativePath.cast<Int8>());
    if (result != 0) {
      final int error = _libc.errno;
      if (error != _enoent) {
        throw _socketException('unlink() failed for "$path"', error);
      }
    }
  } finally {
    calloc.free(nativePath);
  }
}

void _closeFd(int fd) {
  if (fd >= 0) {
    _libc.close(fd);
  }
}

SocketException _socketException(String message, int errno) {
  return SocketException(message, osError: OSError('errno=$errno', errno));
}

final _UnixPollReactor _pollReactor = _UnixPollReactor();
final _UnixsockNativeShim _nativeShim = _UnixsockNativeShim();
final _LibC _libc = _LibC();

final class _UnixPollReactor {
  _UnixPollReactor() {
    _mainPort.listen(_onMainMessage);
  }

  final ReceivePort _mainPort = ReceivePort();
  final Map<int, void Function(int)> _handlers = <int, void Function(int)>{};

  SendPort? _commandPort;
  Isolate? _isolate;
  int? _wakeWriteFd;
  int _nextId = 1;
  int _registrations = 0;
  Completer<void>? _startCompleter;
  Completer<void>? _stopCompleter;

  Future<void> ensureRunning() async {
    if (_commandPort != null) {
      return;
    }
    if (_startCompleter != null) {
      return _startCompleter!.future;
    }

    final completer = Completer<void>();
    _startCompleter = completer;
    _isolate = await Isolate.spawn(
      _pollReactorIsolateMain,
      _mainPort.sendPort,
      errorsAreFatal: false,
    );
    await completer.future;
  }

  Future<int> register({
    required int fd,
    required int events,
    required void Function(int revents) onEvent,
  }) async {
    await ensureRunning();
    return registerSync(fd: fd, events: events, onEvent: onEvent);
  }

  int registerSync({
    required int fd,
    required int events,
    required void Function(int revents) onEvent,
  }) {
    final SendPort? commandPort = _commandPort;
    if (commandPort == null) {
      throw StateError('Poll reactor is not running.');
    }

    final int id = _nextId++;
    _handlers[id] = onEvent;
    _registrations++;

    commandPort.send(<String, Object?>{
      'op': 'register',
      'id': id,
      'fd': fd,
      'events': events,
    });
    _wake();
    return id;
  }

  void updateInterest(int id, int events) {
    if (!_handlers.containsKey(id)) {
      return;
    }
    final SendPort? commandPort = _commandPort;
    if (commandPort == null) {
      return;
    }
    commandPort.send(<String, Object?>{
      'op': 'update',
      'id': id,
      'events': events,
    });
    _wake();
  }

  Future<void> unregister(int id) async {
    if (_handlers.remove(id) == null) {
      return;
    }

    if (_registrations > 0) {
      _registrations--;
    }

    final SendPort? commandPort = _commandPort;
    if (commandPort != null) {
      commandPort.send(<String, Object?>{
        'op': 'unregister',
        'id': id,
      });
      _wake();
    }

    if (_registrations == 0) {
      await _shutdown();
    }
  }

  Future<void> shutdownIfIdle() async {
    if (_registrations == 0) {
      await _shutdown();
    }
  }

  Future<void> _shutdown() async {
    final SendPort? commandPort = _commandPort;
    if (commandPort == null) {
      _cleanup();
      return;
    }

    final completer = _stopCompleter ?? Completer<void>();
    _stopCompleter ??= completer;

    commandPort.send(<String, Object?>{'op': 'shutdown'});
    _wake();

    try {
      await completer.future.timeout(const Duration(seconds: 1));
    } on TimeoutException {
      _isolate?.kill(priority: Isolate.immediate);
      _cleanup();
    }
  }

  void _wake() {
    final int? writeFd = _wakeWriteFd;
    if (writeFd == null) {
      return;
    }
    final Pointer<Uint8> byte = calloc<Uint8>();
    try {
      byte.value = 1;
      _libc.write(writeFd, byte.cast<Void>(), 1);
    } finally {
      calloc.free(byte);
    }
  }

  void _onMainMessage(dynamic message) {
    if (message is! List<Object?> || message.isEmpty) {
      return;
    }

    final String? type = message.first as String?;
    if (type == 'ready') {
      _commandPort = message[1] as SendPort;
      _wakeWriteFd = message[2] as int;
      _startCompleter?.complete();
      _startCompleter = null;
      return;
    }

    if (type == 'event') {
      final int id = message[1] as int;
      final int revents = message[2] as int;
      final handler = _handlers[id];
      if (handler != null) {
        handler(revents);
      }
      return;
    }

    if (type == 'stopped') {
      _stopCompleter?.complete();
      _cleanup();
    }
  }

  void _cleanup() {
    _commandPort = null;
    _wakeWriteFd = null;
    _isolate = null;
    _startCompleter = null;
    _stopCompleter = null;
    _registrations = 0;
    _handlers.clear();
  }
}

void _pollReactorIsolateMain(SendPort mainSendPort) {
  final ReceivePort commandPort = ReceivePort();
  final _PollReactorLoop loop = _PollReactorLoop(mainSendPort, commandPort);
  loop.start();
}

final class _PollReactorLoop {
  _PollReactorLoop(this._mainSendPort, this._commandPort) {
    final Pointer<Int32> pipeFds = calloc<Int32>(2);
    try {
      if (_libc.pipe(pipeFds) != 0) {
        throw _socketException('pipe() failed', _libc.errno);
      }
      _wakeReadFd = pipeFds[0];
      _wakeWriteFd = pipeFds[1];
    } finally {
      calloc.free(pipeFds);
    }

    _commandPort.listen((dynamic message) {
      if (message is Map) {
        _pendingCommands.add(message.cast<String, Object?>());
      }
    });

    _mainSendPort.send(<Object?>['ready', _commandPort.sendPort, _wakeWriteFd]);
  }

  final SendPort _mainSendPort;
  final ReceivePort _commandPort;
  final List<Map<String, Object?>> _pendingCommands = <Map<String, Object?>>[];
  final Map<int, _ReactorWatch> _watches = <int, _ReactorWatch>{};

  late final int _wakeReadFd;
  late final int _wakeWriteFd;
  bool _running = true;

  void start() {
    Timer.run(_step);
  }

  void _step() {
    _applyPendingCommands();
    if (!_running) {
      _stop();
      return;
    }

    final List<int> ids = _watches.keys.toList(growable: false);
    final int count = ids.length + 1;
    final Pointer<_PollFd> pollFds = calloc<_PollFd>(count);

    try {
      pollFds[0]
        ..fd = _wakeReadFd
        ..events = _pollIn
        ..revents = 0;

      for (int index = 0; index < ids.length; index++) {
        final _ReactorWatch watch = _watches[ids[index]]!;
        pollFds[index + 1]
          ..fd = watch.fd
          ..events = watch.events
          ..revents = 0;
      }

      final int ready = _libc.poll(pollFds, count, -1);
      if (ready < 0) {
        if (_libc.errno != _eintr) {
          _mainSendPort.send(<Object?>['error', _libc.errno]);
        }
      } else if (ready > 0) {
        final int controlEvents = pollFds[0].revents;
        if ((controlEvents & _pollIn) != 0) {
          _drainWakePipe();
        }
        if ((controlEvents & (_pollErr | _pollHup | _pollNVal)) != 0) {
          _running = false;
        }

        for (int index = 0; index < ids.length; index++) {
          final int revents = pollFds[index + 1].revents;
          if (revents != 0) {
            _mainSendPort.send(<Object?>['event', ids[index], revents]);
          }
        }
      }
    } finally {
      calloc.free(pollFds);
    }

    if (_running) {
      Timer.run(_step);
    } else {
      _stop();
    }
  }

  void _applyPendingCommands() {
    if (_pendingCommands.isEmpty) {
      return;
    }

    for (final Map<String, Object?> command in _pendingCommands) {
      final String? op = command['op'] as String?;
      if (op == 'register') {
        _watches[command['id']! as int] = _ReactorWatch(
          command['fd']! as int,
          command['events']! as int,
        );
      } else if (op == 'update') {
        final int id = command['id']! as int;
        final _ReactorWatch? watch = _watches[id];
        if (watch != null) {
          watch.events = command['events']! as int;
        }
      } else if (op == 'unregister') {
        _watches.remove(command['id']! as int);
      } else if (op == 'shutdown') {
        _running = false;
      }
    }

    _pendingCommands.clear();
  }

  void _drainWakePipe() {
    final Pointer<Uint8> buffer = calloc<Uint8>(64);
    try {
      _libc.read(_wakeReadFd, buffer.cast<Void>(), 64);
    } finally {
      calloc.free(buffer);
    }
  }

  void _stop() {
    _commandPort.close();
    _closeFd(_wakeReadFd);
    _closeFd(_wakeWriteFd);
    _mainSendPort.send(const <Object?>['stopped']);
    Isolate.exit();
  }
}

final class _ReactorWatch {
  _ReactorWatch(this.fd, this.events);

  final int fd;
  int events;
}

final class _UnixsockNativeShim {
  _UnixsockSetNonBlockingDart? _setNonBlocking;
  Object? _loadError;

  int setNonBlocking(int fd, bool enabled) {
    _ensureLoaded();
    final _UnixsockSetNonBlockingDart? setter = _setNonBlocking;
    if (setter == null) {
      throw UnsupportedError(
        'unixsock native shim is unavailable on this runtime. '
        'Load the package in a Flutter app (ios/macos) so '
        'the plugin native library can be bundled and loaded. '
        'loadError=$_loadError',
      );
    }
    return setter(fd, enabled ? 1 : 0);
  }

  void _ensureLoaded() {
    if (_setNonBlocking != null || _loadError != null) {
      return;
    }
    try {
      final DynamicLibrary library = _openUnixsockShimLibrary();
      _setNonBlocking = library.lookupFunction<_UnixsockSetNonBlockingNative,
          _UnixsockSetNonBlockingDart>('unixsock_set_nonblocking');
    } catch (error) {
      _loadError = error;
    }
  }
}

DynamicLibrary _openUnixsockShimLibrary() {
  final List<String> names = <String>[
    if (Platform.isMacOS || Platform.isIOS) 'unixsock.framework/unixsock',
  ];

  Object? lastError;
  for (final String name in names) {
    try {
      return DynamicLibrary.open(name);
    } on ArgumentError catch (error) {
      lastError = error;
    }
  }

  try {
    return DynamicLibrary.process();
  } on ArgumentError catch (error) {
    lastError = error;
  }

  throw UnsupportedError(
    'Failed to load unixsock native shim library: $lastError',
  );
}

final class _LibC {
  _LibC() : _lib = _openLibC() {
    socket = _lib.lookupFunction<_SocketNative, _SocketDart>('socket');
    connect = _lib.lookupFunction<_ConnectNative, _ConnectDart>('connect');
    bind = _lib.lookupFunction<_BindNative, _BindDart>('bind');
    listen = _lib.lookupFunction<_ListenNative, _ListenDart>('listen');
    accept = _lib.lookupFunction<_AcceptNative, _AcceptDart>('accept');
    try {
      accept4 = _lib.lookupFunction<_Accept4Native, _Accept4Dart>('accept4');
    } on ArgumentError {
      accept4 = null;
    }
    close = _lib.lookupFunction<_CloseNative, _CloseDart>('close');
    pipe = _lib.lookupFunction<_PipeNative, _PipeDart>('pipe');
    read = _lib.lookupFunction<_ReadNative, _ReadDart>('read');
    write = _lib.lookupFunction<_WriteNative, _WriteDart>('write');
    recv = _lib.lookupFunction<_RecvNative, _RecvDart>('recv');
    send = _lib.lookupFunction<_SendNative, _SendDart>('send');
    poll = _lib.lookupFunction<_PollNative, _PollDart>('poll');
    shutdown = _lib.lookupFunction<_ShutdownNative, _ShutdownDart>('shutdown');
    getsockopt = _lib.lookupFunction<_GetSockOptNative, _GetSockOptDart>(
      'getsockopt',
    );
    setsockopt = _lib.lookupFunction<_SetSockOptNative, _SetSockOptDart>(
      'setsockopt',
    );
    unlink = _lib.lookupFunction<_UnlinkNative, _UnlinkDart>('unlink');
    _errnoLocation = _lookupErrnoFunction(_lib);
  }

  final DynamicLibrary _lib;
  late final _SocketDart socket;
  late final _ConnectDart connect;
  late final _BindDart bind;
  late final _ListenDart listen;
  late final _AcceptDart accept;
  late final _Accept4Dart? accept4;
  late final _CloseDart close;
  late final _PipeDart pipe;
  late final _ReadDart read;
  late final _WriteDart write;
  late final _RecvDart recv;
  late final _SendDart send;
  late final _PollDart poll;
  late final _ShutdownDart shutdown;
  late final _GetSockOptDart getsockopt;
  late final _SetSockOptDart setsockopt;
  late final _UnlinkDart unlink;
  late final _ErrnoLocationDart _errnoLocation;

  int get errno => _errnoLocation().value;
}

DynamicLibrary _openLibC() {
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }

  final candidates = <String>[
    if (Platform.isMacOS) '/usr/lib/libSystem.B.dylib',
    if (Platform.isAndroid) 'libc.so',
    if (Platform.isLinux) 'libc.so.6',
    if (Platform.isLinux) 'libc.so',
  ];

  for (final name in candidates) {
    try {
      return DynamicLibrary.open(name);
    } on ArgumentError {
      // Keep trying fallbacks.
    }
  }
  return DynamicLibrary.process();
}

_ErrnoLocationDart _lookupErrnoFunction(DynamicLibrary library) {
  final symbols = <String>[
    if (Platform.isMacOS || Platform.isIOS) '__error',
    if (Platform.isLinux || Platform.isAndroid) '__errno_location',
    if (Platform.isLinux || Platform.isAndroid) '__errno',
  ];

  for (final symbol in symbols) {
    try {
      return library.lookupFunction<_ErrnoLocationNative, _ErrnoLocationDart>(
        symbol,
      );
    } on ArgumentError {
      // Try next symbol.
    }
  }

  throw UnsupportedError(
    'Failed to resolve errno symbol for current platform.',
  );
}

final class _PollFd extends Struct {
  @Int32()
  external int fd;

  @Int16()
  external int events;

  @Int16()
  external int revents;
}

typedef _SocketNative = Int32 Function(Int32, Int32, Int32);
typedef _SocketDart = int Function(int, int, int);

typedef _ConnectNative = Int32 Function(Int32, Pointer<Uint8>, Uint32);
typedef _ConnectDart = int Function(int, Pointer<Uint8>, int);

typedef _BindNative = Int32 Function(Int32, Pointer<Uint8>, Uint32);
typedef _BindDart = int Function(int, Pointer<Uint8>, int);

typedef _ListenNative = Int32 Function(Int32, Int32);
typedef _ListenDart = int Function(int, int);

typedef _AcceptNative = Int32 Function(Int32, Pointer<Void>, Pointer<Uint32>);
typedef _AcceptDart = int Function(int, Pointer<Void>, Pointer<Uint32>);
typedef _Accept4Native = Int32 Function(
    Int32, Pointer<Void>, Pointer<Uint32>, Int32);
typedef _Accept4Dart = int Function(int, Pointer<Void>, Pointer<Uint32>, int);

typedef _CloseNative = Int32 Function(Int32);
typedef _CloseDart = int Function(int);

typedef _PipeNative = Int32 Function(Pointer<Int32>);
typedef _PipeDart = int Function(Pointer<Int32>);

typedef _ReadNative = IntPtr Function(Int32, Pointer<Void>, IntPtr);
typedef _ReadDart = int Function(int, Pointer<Void>, int);

typedef _WriteNative = IntPtr Function(Int32, Pointer<Void>, IntPtr);
typedef _WriteDart = int Function(int, Pointer<Void>, int);

typedef _RecvNative = IntPtr Function(Int32, Pointer<Void>, IntPtr, Int32);
typedef _RecvDart = int Function(int, Pointer<Void>, int, int);

typedef _SendNative = IntPtr Function(Int32, Pointer<Void>, IntPtr, Int32);
typedef _SendDart = int Function(int, Pointer<Void>, int, int);

typedef _PollNative = Int32 Function(Pointer<_PollFd>, UintPtr, Int32);
typedef _PollDart = int Function(Pointer<_PollFd>, int, int);

typedef _ShutdownNative = Int32 Function(Int32, Int32);
typedef _ShutdownDart = int Function(int, int);

typedef _GetSockOptNative = Int32 Function(
    Int32, Int32, Int32, Pointer<Void>, Pointer<Uint32>);
typedef _GetSockOptDart = int Function(
    int, int, int, Pointer<Void>, Pointer<Uint32>);

typedef _SetSockOptNative = Int32 Function(
    Int32, Int32, Int32, Pointer<Void>, Uint32);
typedef _SetSockOptDart = int Function(int, int, int, Pointer<Void>, int);

typedef _UnlinkNative = Int32 Function(Pointer<Int8>);
typedef _UnlinkDart = int Function(Pointer<Int8>);

typedef _ErrnoLocationNative = Pointer<Int32> Function();
typedef _ErrnoLocationDart = Pointer<Int32> Function();

typedef _UnixsockSetNonBlockingNative = Int32 Function(Int32, Int32);
typedef _UnixsockSetNonBlockingDart = int Function(int, int);

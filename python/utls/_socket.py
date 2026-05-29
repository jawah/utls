from __future__ import annotations

import socket
from typing import Any

from ._facade import MemoryBIO, SSLContext, SSLObject, SSLSession, _ErrorRemapping
from .exceptions import (
    SSLEOFError,
    SSLWantReadError,
    SSLWantWriteError,
    SSLZeroReturnError,
)


class SSLSocket:
    """Blocking, socket-backed TLS connection.

    Note: this class deliberately does *not* subclass ``socket.socket`` (the
    stdlib does, but that requires fragile C-extension footwork). For most
    code that does ``with ctx.wrap_socket(s) as ssock: ssock.sendall(...)``
    the duck-typed surface here is indistinguishable.
    """

    def __init__(
        self,
        sock: socket.socket,
        context: SSLContext,
        server_hostname: str | None,
        do_handshake_on_connect: bool,
        suppress_ragged_eofs: bool,
        session: SSLSession | None,
        server_side: bool = False,
    ) -> None:
        self._sock = sock
        self._context = context
        self._server_side = server_side
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._io_refs = 0
        self._closed = False
        self._incoming = MemoryBIO()
        self._outgoing = MemoryBIO()
        self._sslobj: SSLObject = context.wrap_bio(
            self._incoming,
            self._outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
            session=session,
        )
        self._handshake_done = False
        if do_handshake_on_connect:
            self.do_handshake()

    def _flush_outgoing(self) -> None:
        pending = self._outgoing.pending
        if pending:
            data = self._outgoing.read(-1)
            self._sock.sendall(data)

    # Default pull size for ``_feed_incoming``. Picked to be large enough
    # that a single user-level ``recv(n)`` for typical ``n`` (16 KiB - 1 MiB)
    # rarely needs more than one socket round-trip, while still small
    # enough to keep latency tolerable on slow networks. The MemoryBIO
    # accepts as much as we hand it, so over-fetching just buffers ahead.
    _DEFAULT_PULL_SIZE = 65536

    def _feed_incoming(self, hint: int = 0) -> None:
        # Pull at least ``hint`` bytes if the caller knows it wants a big
        # read (e.g. a 1 MiB ``recv``). One large socket recv is far cheaper
        # than many small ones - see the rtls-inspired batching note in
        # ``Connection::read`` (Rust side).
        want = max(hint, self._DEFAULT_PULL_SIZE)
        # NB: stdlib ssl lets socket-level OSError (incl. socket.timeout /
        # TimeoutError and BlockingIOError on non-blocking fds) propagate
        # untouched. Wrapping them as SSLError breaks every HTTP client
        # that catches TimeoutError separately for retry/backoff logic.
        chunk = self._sock.recv(want)
        if not chunk:
            self._incoming.write_eof()
            return
        self._incoming.write(chunk)

    def do_handshake(self) -> None:
        if self._handshake_done:
            return  # Defensive: idempotency guard for re-entrant callers.
        while True:
            try:
                self._sslobj.do_handshake()
                self._flush_outgoing()
                self._handshake_done = True
                return
            except SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()
                if self._incoming.eof:
                    raise SSLEOFError(
                        "peer closed connection mid-handshake"
                    ) from None  # Defensive: peer racing the TCP teardown against the handshake.
            except SSLWantWriteError:  # Defensive: WANT_WRITE here means the kernel send buffer filled up mid-handshake; unreachable on loopback.
                self._flush_outgoing()
            except (
                Exception
            ):  # Defensive: best-effort alert flush before re-raising the fatal error.
                # A fatal error (cert verification failure, SNI callback
                # alert, protocol error) leaves an outgoing alert record
                # buffered in MemoryBIO. Flush it best-effort so the peer
                # sees the alert instead of just a socket close, then
                # re-raise. Swallow OSError on the flush: if the socket is
                # already gone, the peer won't see the alert anyway.
                try:
                    self._flush_outgoing()
                except OSError:
                    pass
                raise

    def recv(self, n: int = 1024) -> bytes:
        while True:
            try:
                return self._sslobj.read(n)
            except SSLZeroReturnError:  # Defensive: needs a peer that actually issues close_notify.
                # Stdlib parity: a clean close_notify from the peer is
                # signaled to the caller as an empty read, NOT an exception.
                return b""
            except SSLWantReadError:
                self._flush_outgoing()
                # Pass the user-requested size as a hint so big recvs
                # collapse into one socket round-trip instead of N*16 KiB.
                self._feed_incoming(hint=n)
                if self._incoming.eof:
                    # Stdlib parity: with suppress_ragged_eofs, treat a
                    # raggedly-closed connection as an empty read.
                    if self._suppress_ragged_eofs:
                        return b""
                    raise SSLEOFError(
                        "peer closed connection without close_notify"
                    ) from None  # Defensive: unsuppressed ragged-EOF, needs a peer that drops TCP mid-stream.
            except SSLWantWriteError:  # Defensive: WANT_WRITE during recv is a TLS 1.2 renegotiation path that BoringSSL does not trigger client-side.
                self._flush_outgoing()

    def send(self, data: bytes) -> int:
        while True:
            try:
                with _ErrorRemapping():
                    n = self._sslobj.write(data)
                self._flush_outgoing()
                return n
            except (
                SSLWantWriteError
            ):  # Defensive: kernel send buffer full mid-write, rare on loopback.
                self._flush_outgoing()
            except (
                SSLWantReadError
            ):  # Defensive: TLS 1.2 renegotiation path; BoringSSL does not trigger it.
                self._feed_incoming()

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            sent += self.send(view[sent:])  # type: ignore[arg-type]

    #
    # ``ssl.SSLSocket`` exposes ``read``/``write`` as aliases for ``recv``/
    # ``send`` (see CPython ``Modules/_ssl.c``). Some libraries (notably
    # ``urllib3.contrib.pyopenssl``-style adapters and a handful of HTTP/2
    # wire-test suites) call these by name rather than ``recv``/``send``.

    def read(self, n: int = 1024, buffer: bytearray | None = None) -> int | bytes:
        """Stdlib alias for :meth:`recv` / :meth:`recv_into`.

        With ``buffer=None`` reads up to ``n`` bytes and returns them.
        With a writable ``buffer``, reads at most ``n`` bytes into it and
        returns the number of bytes read (matches ``ssl.SSLSocket.read``).
        """
        if buffer is None:
            return self.recv(n)
        return self.recv_into(buffer, n)

    def write(self, data: bytes) -> int:
        """Stdlib alias for :meth:`send` (returns bytes written)."""
        return self.send(data)

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """Receive up to ``nbytes`` bytes into ``buffer``.

        ``flags`` is accepted for socket-API parity but must be ``0`` (the
        stdlib silently ignores it too on TLS sockets).
        """
        if flags != 0:
            raise ValueError(  # Defensive: API parity guard, callers never pass flags.
                "non-zero flags not allowed on TLS sockets"
            )
        view = memoryview(buffer)
        if nbytes <= 0 or nbytes > len(view):
            nbytes = len(view)
        if nbytes == 0:
            return 0  # Defensive: zero-length buffer short-circuit.
        data = self.recv(nbytes)
        n = len(data)
        view[:n] = data
        return n

    #
    # ``ssl.SSLSocket`` raises ``ValueError`` for datagram / OOB ops because
    # TLS framing only makes sense on a stream. Mirror that contract.

    def recvfrom(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("recvfrom not allowed on TLS-wrapped sockets")

    def recvfrom_into(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError(  # Defensive: API parity guard mirroring recvfrom.
            "recvfrom_into not allowed on TLS-wrapped sockets"
        )

    def sendto(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("sendto not allowed on TLS-wrapped sockets")

    def recvmsg(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("recvmsg not allowed on TLS-wrapped sockets")

    def recvmsg_into(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("recvmsg_into not allowed on TLS-wrapped sockets")

    def sendmsg(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("sendmsg not allowed on TLS-wrapped sockets")

    def unwrap(
        self,
    ) -> socket.socket:  # Defensive: full unwrap loop requires a real peer round-trip.
        """Bidirectional shutdown: send our ``close_notify`` and wait for the
        peer's. When ``suppress_ragged_eofs=True`` (the default) a peer that closes
        the connection without sending its own ``close_notify`` is tolerated.
        """
        while True:
            try:
                done = self._sslobj.unwrap()
                self._flush_outgoing()
                if done:
                    return self._sock
                # Half-shutdown: our notify is out, now wait for the peer's.
                self._feed_incoming()
            except SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()
            except SSLWantWriteError:
                self._flush_outgoing()
                continue
            if self._incoming.eof:  # only reached after a half-shutdown EOF.
                if self._suppress_ragged_eofs:
                    return self._sock
                raise SSLEOFError(
                    "peer closed connection without close_notify during shutdown"
                ) from None

    def close(self) -> None:
        # Mirror stdlib's deferred-close semantics: an outstanding
        # ``SocketIO`` returned by ``makefile()`` keeps the underlying
        # socket alive until *its* close drops the refcount to zero.
        # Without this, code like ``f = sock.makefile(); sock.close();
        # f.read()`` would lose the underlying socket before the file
        # object is done with it.
        self._closed = True
        if self._io_refs <= 0:
            self._real_close()

    def _real_close(self) -> None:
        try:
            self._sock.close()
        except OSError:  # Defensive: socket may already be in a broken state.
            pass

    def _decref_socketios(self) -> None:
        # Called by ``socket.SocketIO.close()`` to release the reference
        # taken in ``makefile()``. Defined as a no-op on a raw socket if
        # the counter is already at zero; only triggers the real close
        # once the user has also called ``self.close()``.
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed:
            self._real_close()

    def selected_alpn_protocol(self) -> str | None:
        return self._sslobj.selected_alpn_protocol()

    def cipher(self) -> tuple[str, str, int] | None:
        return self._sslobj.cipher()

    def version(self) -> str | None:
        return self._sslobj.version()

    def getpeercert(self, binary_form: bool = False) -> Any:
        return self._sslobj.getpeercert(binary_form=binary_form)

    def get_verified_chain(self) -> list:
        return self._sslobj.get_verified_chain()  # Defensive: passthrough

    def get_unverified_chain(self) -> list:
        return (
            self._sslobj.get_unverified_chain()
        )  # Defensive: thin delegate, same as get_verified_chain.

    def get_fingerprint(self):  # type: ignore[no-untyped-def]
        """See :meth:`utls.SSLObject.get_fingerprint`."""
        return self._sslobj.get_fingerprint()

    def compression(self) -> None:
        return (  # Defensive: thin delegate, BoringSSL always returns None.
            self._sslobj.compression()
        )

    @property
    def context(self) -> SSLContext:
        return self._context

    @property
    def server_hostname(self) -> str | None:
        return self._sslobj.server_hostname

    @property
    def session(self) -> SSLSession | None:
        return (  # Defensive: thin delegate, needs a real handshake to return non-None.
            self._sslobj.session
        )

    @property
    def session_reused(self) -> bool:
        return self._sslobj.session_reused  # Defensive: thin delegate, needs a resumed handshake.

    @property
    def type(self) -> int:
        """The underlying socket type (e.g. :data:`socket.SOCK_STREAM`).

        Mirrors :attr:`socket.socket.type`. Required by callers that route on
        the socket kind - notably :mod:`urllib3`'s connection pool, which
        asserts ``isinstance(sock, ssl.SSLSocket) and sock.type == SOCK_STREAM``
        before reusing a connection.
        """
        return self._sock.type

    @property
    def family(self) -> int:
        """Address family of the underlying socket (e.g. :data:`socket.AF_INET`)."""
        return self._sock.family

    @property
    def proto(self) -> int:
        """Protocol number of the underlying socket (almost always ``0``)."""
        return self._sock.proto

    def fileno(self) -> int:
        return self._sock.fileno()

    def getpeername(self) -> Any:
        return self._sock.getpeername()

    def getsockname(self) -> Any:
        return self._sock.getsockname()  # Defensive: thin socket pass-through.

    def getsockopt(self, *args: Any, **kwargs: Any) -> Any:
        """Pass-through to the underlying TCP socket. urllib3-future calls
        this to probe ``SO_KEEPALIVE`` state right after the handshake."""
        return self._sock.getsockopt(*args, **kwargs)

    def setsockopt(self, *args: Any, **kwargs: Any) -> Any:
        return self._sock.setsockopt(*args, **kwargs)

    def shutdown(self, how: int) -> None:
        """Pass-through to ``socket.socket.shutdown``. Stdlib's
        :class:`ssl.SSLSocket` inherits this from :class:`socket.socket`;
        urllib3-future's DoH/DoT resolver calls ``self._socket.shutdown(0)``
        in its close path and crashed with ``AttributeError`` here until
        we exposed the delegate. Note this is the *TCP* half-close
        (``SHUT_RD`` / ``SHUT_WR`` / ``SHUT_RDWR``), not the TLS
        ``close_notify`` exchange - the latter is :meth:`unwrap`.
        """
        self._sock.shutdown(how)

    def settimeout(self, t: float | None) -> None:
        self._sock.settimeout(t)

    def gettimeout(self) -> float | None:
        return self._sock.gettimeout()

    def setblocking(
        self, flag: bool
    ) -> None:  # Defensive: non-blocking mode is intentionally refused.
        if not flag:
            # Non-blocking sockets need the caller to drive the want-read /
            # want-write loop themselves; this class is intentionally
            # blocking-only. Recommend wrap_bio for non-blocking usage.
            raise NotImplementedError(
                "SSLSocket is blocking-only; use SSLContext.wrap_bio for non-blocking or async I/O."
            )
        self._sock.setblocking(True)

    def makefile(
        self, mode: str = "r", *args: Any, **kwargs: Any
    ) -> Any:  # Defensive: thin delegate, exercised by stdlib http.client tests.
        # Stdlib's ``socket.makefile()`` bumps ``_io_refs`` *before* it
        # constructs the :class:`socket.SocketIO`, because ``SocketIO.close``
        # always decrements via ``_decref_socketios``. Mirror that here so
        # the ref accounting balances after ``f.close()``.
        self._io_refs += 1
        return socket.SocketIO(self, mode)  # type: ignore[arg-type]

    # context-manager sugar
    def __enter__(self) -> SSLSocket:
        return self

    def __exit__(self, *exc: Any) -> None:
        # Stdlib parity: `SSLSocket` inherits `socket.socket.__exit__` which
        # only calls `close()` - the bidirectional `unwrap()` shutdown is
        # explicit (and many test peers close without sending close_notify,
        # which would surface as SSLEOFError on `__exit__`).
        self.close()

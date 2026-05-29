from __future__ import annotations

import os
import ssl as _stdlib_ssl
from typing import Any, Iterable

from . import _utls as _core
from ._fingerprint import Fingerprint
from ._utils import DER_cert_to_PEM_cert
from .constants import (
    CERT_NONE,
    CERT_OPTIONAL,
    CERT_REQUIRED,
    PROTOCOL_TLS,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Options,
    PROTOCOL_SSLv23,
    PROTOCOL_TLSv1,
    PROTOCOL_TLSv1_1,
    PROTOCOL_TLSv1_2,
    Purpose,
    TLSVersion,
)
from .exceptions import (
    SSLCertVerificationError,
    SSLEOFError,
    SSLError,
    SSLWantReadError,
    SSLWantWriteError,
    SSLZeroReturnError,
)


def _tls_version_to_rust_code(v: TLSVersion) -> int:
    """Translate a stdlib-shaped ``TLSVersion`` to the small u8-fit code."""
    iv = int(v)
    if iv == int(TLSVersion.MINIMUM_SUPPORTED):
        return 0
    if iv == int(TLSVersion.MAXIMUM_SUPPORTED):
        return 9
    if iv >= int(TLSVersion.TLSv1_3):
        return 3
    if iv >= int(TLSVersion.TLSv1_2):
        return 2
    # SSLv3 / TLSv1 / TLSv1_1: stdlib accepts the assignment even when
    # the underlying library refuses to negotiate them. We do the same:
    # the value is stored as-is on the Python side, but the FFI sees
    # the floor (TLS 1.2) because that's the lowest BoringSSL will go.
    return 2


def _translate_core_error(exc: BaseException) -> BaseException:
    """Map an ``_utls.CoreError`` into the user-facing exception hierarchy.

    Anything else passes through unchanged.
    """
    if not isinstance(exc, _core.CoreError):
        return exc
    # CoreError.args = (kind, message)
    try:
        kind, message = exc.args[0], exc.args[1]
    except (IndexError, TypeError):  # Defensive: forward-compat fallback
        return SSLError(str(exc))
    cls = {
        "WantRead": SSLWantReadError,
        "WantWrite": SSLWantWriteError,
        "Eof": SSLEOFError,
        "ZeroReturn": SSLZeroReturnError,
        "Verification": SSLCertVerificationError,
        "Protocol": SSLError,
        "Io": SSLError,
    }.get(kind, SSLError)
    if cls is SSLCertVerificationError:
        code = getattr(exc, "verify_code", None)
        return SSLCertVerificationError(message, verify_code=code or None)
    # asyncio's SSL transport on Python 3.8-3.10 catches ssl.SSLError and
    # inspects exc.errno against SSL_ERROR_WANT_READ/WRITE/SYSCALL to decide
    # whether to buffer and retry. Stdlib's _ssl populates errno via
    # OSError(errno, strerror) construction, so we mirror that here.
    errno_map = {
        "WantRead": _stdlib_ssl.SSL_ERROR_WANT_READ,
        "WantWrite": _stdlib_ssl.SSL_ERROR_WANT_WRITE,
        "Io": _stdlib_ssl.SSL_ERROR_SYSCALL,
    }
    errno_val = errno_map.get(kind)
    if errno_val is not None:
        return cls(errno_val, message)
    return cls(message)


class _ErrorRemapping:
    """Context manager that re-raises ``_utls.CoreError`` as the right ``SSLError``."""

    def __enter__(self) -> _ErrorRemapping:
        return self

    def __exit__(self, exc_type, exc, tb):  # type: ignore[no-untyped-def]
        if exc is None:
            return False
        new = _translate_core_error(exc)
        if new is exc:
            return False
        raise new from exc


class MemoryBIO:
    """In-memory bytes ring backing one direction of TLS I/O.

    Mirrors :class:`ssl.MemoryBIO`. Two instances (incoming, outgoing) are
    paired by :meth:`SSLContext.wrap_bio`.
    """

    __slots__ = ("_bio",)

    def __init__(self) -> None:
        self._bio = _core.MemoryBio()

    @property
    def pending(self) -> int:
        return self._bio.pending

    @property
    def eof(self) -> bool:
        return self._bio.eof

    def read(self, n: int = -1) -> bytes:
        with _ErrorRemapping():
            return self._bio.read(n)

    def write(self, data: bytes) -> int:
        with _ErrorRemapping():
            return self._bio.write(data)

    def write_eof(self) -> None:
        self._bio.write_eof()


class SSLSession:
    """Opaque TLS session token. Picklable via the underlying DER blob."""

    __slots__ = ("_session",)

    def __init__(self, _handle: Any) -> None:
        self._session = _handle

    @classmethod
    def from_der(cls, data: bytes) -> SSLSession:
        return cls(_core.Session.from_der(data))

    def to_der(self) -> bytes:
        return self._session.to_der()

    def __reduce__(self) -> tuple[Any, tuple[bytes]]:
        return (SSLSession.from_der, (self.to_der(),))


class Certificate:
    """DER-backed X.509 certificate, decoded lazily.

    Surface mirrors the subset of CPython 3.10+ ``ssl.Certificate`` that
    downstream HTTP clients (notably ``urllib3.future``'s verified-chain
    walker) actually consume:

    * :meth:`public_bytes` - the DER blob in either DER or PEM form.
    * :meth:`get_info`     - the same dict shape as
      :meth:`SSLSocket.getpeercert(binary_form=False)`.

    The companion :class:`utls.SSLContext` *must* be passed in so that the
    decoder runs against the same BoringSSL the rest of the stack is using
    (one ``d2i_X509`` per :meth:`get_info` call; cached afterwards).
    """

    __slots__ = ("_der", "_context", "_info")

    # Match the integer values CPython's ``ssl._ssl`` module uses so callers
    # that pass ``ssl._ssl.ENCODING_PEM`` / ``ENCODING_DER`` keep working.
    ENCODING_PEM = 1
    ENCODING_DER = 2

    def __init__(self, der: bytes, context: SSLContext) -> None:
        if not isinstance(der, (bytes, bytearray, memoryview)):
            raise TypeError("Certificate requires DER-encoded bytes")
        self._der = bytes(der)
        self._context = context
        self._info: dict[str, Any] | None = None

    def public_bytes(self, format: int = 1) -> bytes | str:
        """Return the cert in DER (``ENCODING_DER``) or PEM (``ENCODING_PEM``)
        form. Default matches stdlib (PEM)."""
        if format == self.ENCODING_DER:
            return self._der
        if format == self.ENCODING_PEM:
            return DER_cert_to_PEM_cert(self._der)
        raise ValueError("format must be ENCODING_DER or ENCODING_PEM")

    def get_info(self) -> dict[str, Any]:
        """Return the stdlib ``getpeercert(binary_form=False)``-shaped dict."""
        if self._info is None:
            info = self._context._ctx.decode_cert_der(self._der)
            self._info = info if info is not None else {}
        return self._info

    def __repr__(self) -> str:
        return f"<utls.Certificate ({len(self._der)} bytes DER)>"


class SSLObject:
    """MemoryBIO-backed TLS connection. Created by :meth:`SSLContext.wrap_bio`.

    Two backing-buffer regimes are supported transparently:

    * **Native** - the caller passed two :class:`utls.MemoryBIO` instances.
      The SSL engine reads and writes those buffers directly; no copying.
    * **Adapted** - the caller passed two :class:`ssl.MemoryBIO` instances
      (the stdlib type, used by :mod:`asyncio.sslproto` and friends).
      :class:`ssl.MemoryBIO` is a CPython C type and is not subclassable, so
      we cannot make it share a buffer with our BoringSSL engine. Instead we
      allocate a private pair of Rust BIOs that the SSL engine reads/writes
      and *pump* bytes between the caller's stdlib BIOs and those Rust BIOs
      around every SSL operation. The pumping cost is one ``read``+``write``
      pair per direction per call - small and proportional to the bytes in
      flight.
    """

    __slots__ = (
        "_conn",
        "_context",
        "_incoming",
        "_outgoing",
        "_server_hostname",
        "_session",
        # Set only in the "adapted" regime (see class docstring).
        "_rust_incoming",
        "_rust_outgoing",
        "_pumping",
    )

    def __init__(
        self,
        connection: Any,
        context: SSLContext,
        incoming: Any,  # utls.MemoryBIO or ssl.MemoryBIO
        outgoing: Any,
        server_hostname: str | None,
        session: SSLSession | None,
        rust_incoming: MemoryBIO | None = None,
        rust_outgoing: MemoryBIO | None = None,
    ) -> None:
        self._conn = connection
        self._context = context
        self._incoming = incoming
        self._outgoing = outgoing
        self._server_hostname = server_hostname
        self._session = session
        # When `rust_incoming`/`rust_outgoing` are provided, we are in the
        # "adapted" regime and must pump bytes on every SSL operation.
        self._rust_incoming = rust_incoming
        self._rust_outgoing = rust_outgoing
        self._pumping = rust_incoming is not None

    def _pump_in(self) -> None:
        """Ciphertext flow: stdlib `incoming` -> Rust `incoming`.

        Called immediately before any operation that may cause BoringSSL to
        consume ciphertext (``do_handshake``, ``read``, ``unwrap``).
        """
        if not self._pumping:
            return
        pending = self._incoming.pending
        if pending:
            self._rust_incoming.write(self._incoming.read(pending))  # type: ignore[union-attr]
        if self._incoming.eof:
            self._rust_incoming.write_eof()  # type: ignore[union-attr]

    def _pump_out(self) -> None:
        """Ciphertext flow: Rust `outgoing` -> stdlib `outgoing`.

        Called immediately after any operation that may cause BoringSSL to
        produce ciphertext (every public method on this class).
        """
        if not self._pumping:
            return
        pending = self._rust_outgoing.pending  # type: ignore[union-attr]
        if pending:
            self._outgoing.write(self._rust_outgoing.read(pending))  # type: ignore[union-attr]

    def do_handshake(self) -> None:
        self._pump_in()
        try:
            with _ErrorRemapping():
                self._conn.do_handshake()
        finally:
            self._pump_out()

    def read(self, n: int = 1024, buffer: Any = None) -> Any:
        """Mirrors :meth:`ssl.SSLObject.read`.

        When *buffer* is ``None`` (the default), returns up to *n* bytes
        as a ``bytes`` object - stdlib behavior. When *buffer* is a
        writable bytes-like object (``bytearray`` / ``memoryview`` /
        ``ctypes`` array / ...), reads up to ``len(buffer)`` bytes into
        it and returns the number of bytes read as an ``int``.

        The buffer form is what :mod:`asyncio.sslproto` uses on Python
        3.11+ (``self._sslobj.read(wants, buf)`` in its
        ``_do_read__buffered`` path); without this overload that call
        crashes with ``TypeError: SSLObject.read() takes from 1 to 2
        positional arguments but 3 were given``.
        """
        self._pump_in()
        try:
            with _ErrorRemapping():
                if buffer is None:
                    return self._conn.read(n)
                # Buffer form: stdlib ignores *n* and uses the buffer's
                # length as the read cap. ``memoryview`` lets us write
                # the bytes back without an extra Python-level copy.
                mv = memoryview(buffer)
                if mv.readonly:
                    raise TypeError("read() buffer must be writable")
                cap = len(mv) if mv.ndim == 1 else mv.nbytes
                if cap == 0:
                    return 0
                data = self._conn.read(cap)
                ln = len(data)
                if ln:
                    # Cast to a 1-D byte view so the assignment is valid
                    # even when the caller passed a multi-dim memoryview.
                    mv.cast("B")[:ln] = data
                return ln
        finally:
            self._pump_out()

    def write(self, data: bytes) -> int:
        # The Rust binding takes `&[u8]`, which PyO3 only auto-extracts
        # from `bytes` - not from `memoryview` or `bytearray`. Higher layers
        # (socket.sendall, http.client, etc.) routinely hand us memoryviews,
        # so normalize here. `bytes(mv)` is a single copy and matches what
        # the stdlib `_ssl` module does internally.
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        try:
            with _ErrorRemapping():
                return self._conn.write(data)
        finally:
            self._pump_out()

    def unwrap(self) -> bool:
        """Send (and consume) close_notify.

        Returns ``True`` when the bidirectional shutdown is complete; ``False``
        when our ``close_notify`` was sent but the peer's has not yet arrived
        (the caller must pump more bytes through ``_incoming`` and retry).
        May raise ``SSLWantReadError`` if a round trip is needed.
        """
        self._pump_in()
        try:
            with _ErrorRemapping():
                return self._conn.shutdown()
        finally:
            self._pump_out()

    def pending(self) -> int:
        # Stdlib pending() reports decrypted bytes available; BoringSSL has
        # SSL_pending() but our PyO3 binding doesn't expose it yet. We return
        # the outgoing ciphertext pending count, which is the more useful
        # number for a MemoryBIO-driven loop.
        return self._outgoing.pending

    def selected_alpn_protocol(self) -> str | None:
        return self._conn.selected_alpn()

    def cipher(self) -> tuple[str, str, int] | None:
        return self._conn.cipher()

    def version(self) -> str | None:
        return self._conn.version()

    def compression(self) -> None:
        # BoringSSL never enables TLS compression. Mirror stdlib's contract.
        return None

    def getpeercert(self, binary_form: bool = False) -> Any:
        """Return the peer certificate.

        * ``binary_form=True`` - DER-encoded leaf certificate as :class:`bytes`,
          or ``None`` if the peer presented no certificate (matches stdlib).
        * ``binary_form=False`` - a dict matching :meth:`ssl.SSLSocket.getpeercert`
          with keys ``subject``, ``issuer``, ``version``, ``serialNumber``,
          ``notBefore``, ``notAfter``, and ``subjectAltName`` (when present).
          Returns ``{}`` when the handshake has completed but no cert was
          received (matches stdlib for ``CERT_NONE`` with no cert), or ``None``
          before the handshake completes.

        We deliberately omit a few rarely-consumed extension fields that
        CPython's `_decode_certificate` does emit (OCSP responder URLs, CA
        Issuers, CRL distribution points). Callers needing those should use
        ``binary_form=True`` and parse with the ``cryptography`` package.
        """
        if binary_form:
            chain = self._conn.peer_chain_der()
            return chain[0] if chain else None
        info = self._conn.peer_cert_info()
        return info if info is not None else {}

    def get_verified_chain(self) -> list[Certificate]:
        """Return the verified peer cert chain (leaf first) as
        :class:`Certificate` objects.

        Mirrors :meth:`ssl.SSLObject.get_verified_chain` (Python 3.10+).
        Returns ``[]`` if the handshake has not produced a chain (e.g.
        no peer cert presented under ``CERT_NONE``).
        """
        return [Certificate(der, self._context) for der in self._conn.peer_chain_der()]

    def get_unverified_chain(self) -> list[Certificate]:
        """Same as :meth:`get_verified_chain` for this implementation.

        BoringSSL exposes a single chain post-handshake; we do not retain a
        separate pre-verification copy.
        """
        return self.get_verified_chain()

    @property
    def _sslobj(self) -> SSLObject:
        """Self-alias matching stdlib :class:`ssl.SSLSocket._sslobj`.

        Several ecosystem libraries (notably ``urllib3.future``) reach for
        ``ssl_object._sslobj.get_verified_chain()`` when handed an SSLObject
        directly (from ``transport.get_extra_info('ssl_object')``).
        """
        return self

    @property
    def context(self) -> SSLContext:
        return self._context

    @property
    def server_hostname(self) -> str | None:
        # Client side: the SNI / hostname-verification anchor we configured.
        # Server side: the SNI value the *peer* sent in its ClientHello, if
        # any (mirrors stdlib's behaviour - see ssl._ssl._wrap_bio handling
        # of SNI on the server side).
        if self._server_hostname is not None:
            return self._server_hostname
        if self._conn.is_server():
            return self._conn.peer_sni()
        return None

    @property
    def session(self) -> SSLSession | None:
        h = self._conn.session()
        return SSLSession(h) if h is not None else None

    @property
    def session_reused(self) -> bool:
        return self._conn.session_reused()

    def get_fingerprint(self) -> Fingerprint | None:
        """Return a :class:`Fingerprint` describing the wire-visible TLS state
        of this connection.

        * **Server connection** - the peer's observed ClientHello, captured
          via BoringSSL's ``select_certificate_cb``. Returns ``None`` if no
          ClientHello has been parsed yet (handshake has not started) or if
          parsing failed.
        * **Client connection** - the fingerprint we *sent*, equivalent to
          ``self.context.fingerprint``. Returns ``None`` if the context has
          no fingerprint configured.

        This is an ``utls`` extension - there is no ``ssl`` stdlib equivalent.
        On the server side, treat the result as a **wire fact**, not a
        cryptographic identity: clients can spoof any ClientHello, so
        downstream security decisions must not rely on this value alone.
        """
        if self._conn.is_server():
            handle = self._conn.observed_client_fingerprint()
            return Fingerprint._wrap(handle) if handle is not None else None
        # Client-side: prefer the cached Python wrapper (it carries headers).
        if self._context._fp_py is not None:
            return self._context._fp_py
        handle = self._context._ctx.fingerprint()
        return Fingerprint._wrap(handle) if handle is not None else None

    def ech_accepted(self) -> bool:
        """``True`` iff ECH was offered *and* the server accepted it.

        This is an ``utls`` extension - there is no ``ssl`` stdlib equivalent.
        Returns ``False`` before the handshake completes, when ECH was not
        offered, or when the server fell back to the public name.
        """
        return self._conn.ech_accepted()

    def ech_retry_configs(self) -> bytes | None:
        """Return the server-supplied retry ``ECHConfigList``, if any.

        If the server rejected our ECH config and supplied a fresh one for the
        next attempt, this returns its wire-format bytes; pair with
        :meth:`SSLContext.set_ech_configs` on a fresh context (or a fresh
        connection from this context after re-installing) to retry.
        Returns ``None`` when ECH was accepted, when it was never offered, or
        when the server signalled "ECH rolled back" with an empty retry list.

        This is an ``utls`` extension - there is no ``ssl`` stdlib equivalent.
        """
        return self._conn.ech_retry_configs()


class _SNISslObj:
    """SSLObject-shaped view handed to the user's SNI callback.

    Exposes the two attributes stdlib's SNI callback contract relies on:
    :attr:`server_hostname` and :attr:`context`. Assigning to
    :attr:`context` swaps the in-flight handshake onto a different
    :class:`SSLContext`'s cert chain, ALPN list, verify mode, and TLS 1.3
    cipher selection (via BoringSSL's ``SSL_set_SSL_CTX``).
    """

    __slots__ = ("_view", "_context")

    def __init__(self, view: Any, owner_ctx: SSLContext) -> None:
        self._view = view
        self._context = owner_ctx

    @property
    def server_hostname(self) -> str | None:
        return self._view.server_name

    @property
    def context(self) -> SSLContext:
        return self._context

    @context.setter
    def context(self, new_ctx: SSLContext) -> None:
        if not isinstance(new_ctx, SSLContext):
            raise TypeError(f"context must be a utls.SSLContext, got {type(new_ctx).__name__}")
        # Hand the Rust-side _utls.Context off to the SNI view; this calls
        # SSL_set_SSL_CTX on the live handshake handle.
        self._view.swap_context(new_ctx._ctx)
        self._context = new_ctx


class SSLContext(_stdlib_ssl.SSLContext):
    """Mirrors :class:`ssl.SSLContext` for the client-side subset.

    Inherits from :class:`ssl.SSLContext` so that third-party libraries which
    perform strict ``isinstance(ctx, ssl.SSLContext)`` checks -
    :mod:`asyncio` (``loop.create_connection(ssl=...)``), :mod:`aiohttp`,
    ``requests``' HTTPS adapter, ``urllib3``, and ``httpx`` - accept our
    contexts transparently. The Python-level :class:`property` descriptors
    defined below (``verify_mode``, ``check_hostname``, ``options``,
    ``minimum_version``, ``maximum_version``, ``protocol``) shadow the
    C-level slot descriptors inherited from the stdlib via Python's MRO,
    so every attribute access and every overridden method (``wrap_socket``,
    ``wrap_bio``, ``load_*``, ``set_*``, ...) runs through our BoringSSL
    backend. The stdlib's internal OpenSSL ``SSL_CTX`` allocated by
    ``super().__init__`` is left untouched and unused - a few kilobytes of
    dead state in exchange for ecosystem compatibility.
    """

    # `ssl.SSLContext` is a C type; instances do not get a `__dict__` by
    # default. Declare it explicitly so our Python-side attributes (`_ctx`,
    # `_options`, etc.) can be set per-instance.
    __slots__ = ()

    # Public protocol constants accepted by ``__new__``. Mirrors stdlib.
    _CLIENT_PROTOCOLS = frozenset(
        (
            PROTOCOL_TLS_CLIENT,
            PROTOCOL_TLS,
            PROTOCOL_SSLv23,
            PROTOCOL_TLSv1,
            PROTOCOL_TLSv1_1,
            PROTOCOL_TLSv1_2,
        )
    )
    _SERVER_PROTOCOLS = frozenset((PROTOCOL_TLS_SERVER,))

    def __new__(cls, protocol: int = PROTOCOL_TLS_CLIENT) -> SSLContext:
        # see stdlib ``ssl.SSLContext.__new__``
        is_client = protocol in cls._CLIENT_PROTOCOLS
        is_server = protocol in cls._SERVER_PROTOCOLS
        if not (is_client or is_server):
            raise ValueError(
                f"protocol must be PROTOCOL_TLS_CLIENT or PROTOCOL_TLS_SERVER, got {protocol!r}"
            )
        # Allocate the stdlib parent (its SSL_CTX is unused; see class docstring).
        # We pass the matching stdlib protocol constant so isinstance/repr
        # behave correctly for callers that introspect it.
        stdlib_proto = (
            _stdlib_ssl.PROTOCOL_TLS_SERVER if is_server else _stdlib_ssl.PROTOCOL_TLS_CLIENT
        )
        return super().__new__(cls, stdlib_proto)

    def __init__(self, protocol: int = PROTOCOL_TLS_CLIENT) -> None:
        # NOTE: `ssl.SSLContext` performs all of its C-level initialization in
        # `__new__`; its `__init__` is the inherited `object.__init__` and
        # rejects any extra arguments. We therefore do *not* call
        # `super().__init__(...)` - the parent state is already live by the
        # time control reaches here.
        #
        # The Rust FFI only knows two protocol codes 2client/3server
        if protocol in self._SERVER_PROTOCOLS:
            self._ctx = _core.Context(2 + 1)  # 3: TlsServer
            self._server_side = True
        else:
            self._ctx = _core.Context(2)  # 2: TlsClient
            self._server_side = False
        # Stored Python-side for stdlib-compat reads. Options are honored by
        # translating ``OP_NO_TLSv1_*`` into version-bound constraints
        # (inspired by rtls's `_apply_version_options`); other flags are
        # accepted verbatim for API parity.
        self._options: int = 0
        self._keylog_filename: str | None = None
        # Instance copies of the version bounds tracked Python-side. Defaults
        # match `create_default_context()`. Setting `minimum_version` /
        # `maximum_version` updates the *explicit* slots; the *effective*
        # bounds are recomputed by `_apply_version_options()` whenever either
        # the explicit version or `options` changes.
        self._min_version: TLSVersion = TLSVersion.TLSv1_2
        self._max_version: TLSVersion = TLSVersion.TLSv1_3
        self._explicit_min_version: TLSVersion | None = None
        self._explicit_max_version: TLSVersion | None = None
        # Most recently applied Fingerprint, kept Python-side so
        # `http_header_for_fingerprint()` and the `fingerprint` accessor can
        # return the original profile object - headers and all - instead of a
        # reconstructed view of just the Rust-side TLS state (which would be
        # headerless). Cleared when `set_fingerprint(None)` is called.
        self._fp_py: Fingerprint | None = None
        # Server-side SNI callback installed via set_servername_callback().
        # We keep a Python reference here so the wrapper passed to the Rust
        # side cannot be garbage-collected before the next handshake.
        self._sni_callback: Any = None
        # We do NOT consult SSLKEYLOGFILE - the env var is honored only when
        # the caller explicitly opts in via ``keylog_filename=``.
        # Caller must set the attribute explicitly.

    @property
    def server_side(self) -> bool:
        """Whether this context handshakes as a TLS server."""
        return self._server_side

    @property
    def minimum_version(self) -> TLSVersion:
        # The explicit value (if the user ever assigned one) wins so the
        # getter round-trips stdlib sentinels - including the inverted
        # ``MAXIMUM_SUPPORTED`` form some clients use to mean "no min".
        if self._explicit_min_version is not None:
            return self._explicit_min_version
        return self._min_version

    @minimum_version.setter
    def minimum_version(self, v: TLSVersion) -> None:
        self._explicit_min_version = TLSVersion(int(v))
        self._apply_version_options()

    @property
    def maximum_version(self) -> TLSVersion:
        if self._explicit_max_version is not None:
            return self._explicit_max_version
        return self._max_version

    @maximum_version.setter
    def maximum_version(self, v: TLSVersion) -> None:
        self._explicit_max_version = TLSVersion(int(v))
        self._apply_version_options()

    def _apply_version_options(self) -> None:
        """Recompute the effective TLS version window from the explicit
        ``minimum_version``/``maximum_version`` settings and the currently
        active ``OP_NO_TLSv1_*`` flags, then push the result into the
        underlying ``SSL_CTX``.

        Translation rules (mirrors rtls / matches CPython semantics):

        * ``OP_NO_TLSv1_2`` raises the minimum to TLS 1.3.
        * ``OP_NO_TLSv1_3`` lowers the maximum to TLS 1.2.
        * ``OP_NO_TLSv1`` / ``OP_NO_TLSv1_1`` are accepted but redundant:
          BoringSSL never negotiates TLS 1.0/1.1.
        * ``OP_NO_SSLv2`` / ``OP_NO_SSLv3`` are accepted but no-op:
          BoringSSL never negotiates SSLv2/SSLv3.

        Flags can only *further constrain* the explicit min/max; they
        cannot loosen them. If the combination is unsatisfiable
        (e.g. ``OP_NO_TLSv1_2 | OP_NO_TLSv1_3``) the underlying
        ``set_version_bounds`` call will surface the error as ``SSLError``
        on the next handshake.
        """
        from .constants import OP_NO_TLSv1_2, OP_NO_TLSv1_3

        min_v = (
            self._explicit_min_version
            if self._explicit_min_version is not None
            else TLSVersion.TLSv1_2
        )
        max_v = (
            self._explicit_max_version
            if self._explicit_max_version is not None
            else TLSVersion.TLSv1_3
        )

        if int(min_v) == int(TLSVersion.MAXIMUM_SUPPORTED):
            min_v = TLSVersion.TLSv1_2
        if int(max_v) == int(TLSVersion.MINIMUM_SUPPORTED):
            max_v = TLSVersion.TLSv1_3

        if self._options & OP_NO_TLSv1_2:
            # OP_NO_TLSv1_2 forbids 1.2 -> minimum must be at least 1.3.
            if int(min_v) < int(TLSVersion.TLSv1_3):
                min_v = TLSVersion.TLSv1_3
        if self._options & OP_NO_TLSv1_3:
            # OP_NO_TLSv1_3 forbids 1.3 -> maximum must be at most 1.2.
            if int(max_v) > int(TLSVersion.TLSv1_2):
                max_v = TLSVersion.TLSv1_2

        with _ErrorRemapping():
            self._ctx.set_version_bounds(
                _tls_version_to_rust_code(min_v),
                _tls_version_to_rust_code(max_v),
            )
        self._min_version = min_v
        self._max_version = max_v

    # Defaults (instance attributes set in __init__).

    @property
    def verify_mode(self) -> int:
        return self._ctx.verify_mode()

    @verify_mode.setter
    def verify_mode(self, value: int) -> None:
        if value not in (CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED):
            raise ValueError(f"invalid verify_mode: {value!r}")
        # Stdlib quirk: setting CERT_NONE while check_hostname=True raises.
        if value == CERT_NONE and self.check_hostname:
            raise ValueError("Cannot set verify_mode to CERT_NONE while check_hostname is True")
        with _ErrorRemapping():
            self._ctx.set_verify_mode(value)

    @property
    def check_hostname(self) -> bool:
        return self._ctx.check_hostname()

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        with _ErrorRemapping():
            self._ctx.set_check_hostname(bool(value))

    @property
    def hostname_checks_common_name(self) -> bool:
        raise AttributeError(
            "utls does not support hostname_checks_common_name"
            " (BoringSSL only checks SAN, never CN)"
        )

    @hostname_checks_common_name.setter
    def hostname_checks_common_name(self, value: bool) -> None:
        raise AttributeError(
            "utls does not support hostname_checks_common_name"
            " (BoringSSL only checks SAN, never CN)"
        )

    # ``OP_NO_TLSv1_2`` / ``OP_NO_TLSv1_3`` are translated to
    # ``minimum_version`` / ``maximum_version`` constraints (see
    # ``_apply_version_options``). Other ``OP_*`` flags are stored verbatim
    # for API parity; many (``OP_NO_COMPRESSION``, ``OP_NO_RENEGOTIATION``,
    # ``OP_NO_SSLv2``, ``OP_NO_SSLv3``) describe behavior BoringSSL already
    # enforces unconditionally.

    @property
    def options(self) -> Options:
        return Options(self._options)

    @options.setter
    def options(self, value: int) -> None:
        self._options = int(value)
        self._apply_version_options()

    @property
    def keylog_filename(self) -> str | None:
        return self._keylog_filename

    @keylog_filename.setter
    def keylog_filename(self, value: str | None) -> None:
        if value is not None and not isinstance(value, (str, os.PathLike)):
            raise TypeError("keylog_filename must be str | PathLike | None")
        path = str(value) if value is not None else None
        with _ErrorRemapping():
            self._ctx.set_keylog_filename(path)
        self._keylog_filename = path

    @property
    def verify_flags(self) -> int:
        """X509_V_FLAG_* bitmask currently applied to the verify param.
        Mirrors :attr:`ssl.SSLContext.verify_flags`."""
        return int(self._ctx.verify_flags())

    @verify_flags.setter
    def verify_flags(self, value: int) -> None:
        with _ErrorRemapping():
            self._ctx.set_verify_flags(int(value))

    def load_verify_locations(
        self,
        cafile: str | os.PathLike[str] | None = None,
        capath: str | os.PathLike[str] | None = None,
        cadata: str | bytes | None = None,
    ) -> None:
        # stdlib parity: at least one source is mandatory.
        if cafile is None and capath is None and cadata is None:
            from .exceptions import SSLError

            raise SSLError("load_verify_locations() requires cafile, capath, or cadata")
        if cafile is not None or capath is not None:
            with _ErrorRemapping():
                self._ctx.load_verify_locations(
                    str(cafile) if cafile is not None else None,
                    str(capath) if capath is not None else None,
                )
        if cadata is not None:
            self._load_cadata(cadata)

    def _load_cadata(self, cadata: str | bytes) -> None:
        # Accept either a single PEM string, a single DER blob, or a
        # concatenation of either. Detect by sniffing for the PEM banner.
        if isinstance(cadata, str):
            blob = cadata.encode("ascii")
        else:
            blob = bytes(cadata)
        if b"-----BEGIN" in blob:
            for der in _iter_pem_certs(blob):
                with _ErrorRemapping():
                    self._ctx.add_trusted_cert_der(der)
        else:
            with _ErrorRemapping():
                self._ctx.add_trusted_cert_der(blob)

    def load_cert_chain(
        self,
        certfile: str | bytes | os.PathLike[str],
        keyfile: str | bytes | os.PathLike[str] | None = None,
        password: Any = None,
    ) -> None:
        """Load an X.509 certificate chain and (optionally) its private key.

        Unlike stdlib's `ssl.SSLContext.load_cert_chain`, this accepts PEM
        data in memory as well as filesystem paths - useful when the cert
        material lives in a secret manager (Vault, AWS SM, K8s secrets,
        environment variables, ...) rather than on disk.

        Both ``certfile`` and ``keyfile`` accept any of:

        * ``bytes`` / ``bytearray`` / ``memoryview`` - taken as raw PEM data.
        * ``str`` containing ``-----BEGIN`` - taken as inline PEM text.
        * ``str`` or ``os.PathLike`` otherwise - read from the filesystem.

        ``keyfile=None`` follows stdlib semantics: the private key is read
        from the same source as the certificate (PEM bundle mode).

        ``password`` is a ``str`` / ``bytes`` / ``bytearray`` / zero-arg
        callable used to decrypt password-protected PKCS#8 keys.
        """
        cert_pem = _coerce_pem(certfile, label="certfile")
        key_pem = _coerce_pem(keyfile, label="keyfile") if keyfile is not None else None
        # Mirror stdlib: ``password`` accepts ``bytes`` / ``bytearray`` /
        # ``str`` directly, or a zero-arg callable returning one of those.
        # The callable is invoked once, here, instead of plumbed through to
        # BoringSSL: stdlib's documented contract is that it may be called
        # multiple times by OpenSSL, but in practice every modern libssl
        # invokes it at most once per `PEM_read_bio_PrivateKey`, and caching
        # the result keeps the PyO3 boundary simple.
        pw_bytes: bytes | None
        if password is None:
            pw_bytes = None
        else:
            value = password() if callable(password) else password
            if isinstance(value, str):
                pw_bytes = value.encode("utf-8")
            elif isinstance(value, (bytes, bytearray, memoryview)):
                pw_bytes = bytes(value)
            else:
                raise TypeError(
                    "password must be a string, bytes-like, or a callable "
                    "returning one of those (or None)"
                )
            if len(pw_bytes) > 1024:
                # OpenSSL's default password buffer is small (1024 bytes).
                # We surface this rather than silently truncating - a key
                # decryption failure with a truncated password is far more
                # confusing than an explicit ValueError up front.
                raise ValueError("password must be 1024 bytes or fewer")
        with _ErrorRemapping():
            self._ctx.load_cert_chain(cert_pem, key_pem, pw_bytes)

    def load_default_certs(self, purpose: Purpose = Purpose.SERVER_AUTH) -> None:
        """Load the default set of CA certificates.

        Loads the OS trust store via wassima and additionally honors the
        ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` environment variables (via
        BoringSSL's ``SSL_CTX_set_default_verify_paths``), in line with the
        stdlib `ssl` module behaviour.
        """
        import wassima

        pem_chunks = [DER_cert_to_PEM_cert(der).encode() for der in wassima.root_der_certificates()]
        if pem_chunks:
            self.load_verify_locations(cadata=b"".join(pem_chunks))

        # Mirror CPython: load_default_certs always invokes
        # set_default_verify_paths so SSL_CERT_FILE/SSL_CERT_DIR are honored.
        code = 0 if purpose == Purpose.SERVER_AUTH else 1
        with _ErrorRemapping():
            self._ctx.load_default_certs(code)

    def get_ca_certs(self, binary_form: bool = False) -> list[Any]:
        """Return every CA cert loaded into this context's trust store.

        * ``binary_form=True`` - list of DER-encoded ``bytes``, one per cert.
        * ``binary_form=False`` - list of dicts matching the stdlib shape
          (``{"subject": ..., "issuer": ..., "serialNumber": ..., ...}``),
          parsed from the DER via the same X.509 walker used by
          :meth:`SSLObject.getpeercert`.
        """
        ders = self._ctx.ca_certs_der()
        if binary_form:
            return list(ders)
        # Decoded form: reuse the per-cert walker by spinning each DER through
        # a throwaway ``peer_cert_info`` call. We expose ``decode_cert_der``
        # on the core for this; if it isn't available, fall back to empty
        # dicts to preserve the list length contract.
        decode = getattr(self._ctx, "decode_cert_der", None)
        if decode is None:
            return [{} for _ in ders]
        out: list[Any] = []
        for der in ders:
            info = decode(der)
            out.append(info if info is not None else {})
        return out

    def cert_store_stats(self) -> dict[str, int]:
        """Return ``{"x509": N, "x509_ca": M, "crl": K}`` summarising the
        trust store. Mirrors :meth:`ssl.SSLContext.cert_store_stats`.

        utls reports ``x509`` == ``x509_ca``: every cert added via
        :meth:`load_verify_locations` or :meth:`load_default_certs` is treated
        as a trust anchor by BoringSSL, and there is no separate
        "known-but-not-trusted" bucket.
        """
        x509, crl = self._ctx.cert_store_counts()
        return {"x509": x509, "x509_ca": x509, "crl": crl}

    def set_alpn_protocols(self, protocols: Iterable[str]) -> None:
        protos = list(protocols)
        with _ErrorRemapping():
            self._ctx.set_alpn_protocols(protos)

    def set_ciphers(self, ciphers: str) -> None:
        """Install an OpenSSL-style cipher list. Silently do nothing
        if user set a specific fingerprint!
        """
        if self._fp_py is not None:
            import warnings

            warnings.warn(
                "set_ciphers() ignored: a fingerprint is active and "
                "controls the ClientHello cipher list. Use "
                "Fingerprint(cipher_suites=...) for customisation.",
                UserWarning,
                stacklevel=2,
            )
            return
        with _ErrorRemapping():
            self._ctx.set_ciphers(ciphers)

    def session_stats(self) -> dict[str, int]:
        # Stdlib parity stub: BoringSSL doesn't track client-side resumption
        # counters the way OpenSSL does.
        return {}

    def set_ecdh_curve(self, curve_name: str) -> None:
        """Restrict (EC)DHE to the named curve.

        Mirrors :meth:`ssl.SSLContext.set_ecdh_curve`. A single curve name
        (``"prime256v1"`` / ``"X25519"`` / ``"secp384r1"`` / ...) is accepted;
        for backward compatibility we also accept the OpenSSL colon-separated
        form (``"X25519:P-256"``) so callers porting from OpenSSL configs do
        not have to rewrite their strings.

        Most useful on a server context (it constrains the groups the server
        will accept for key agreement); on a client context it constrains the
        groups offered, but the active :class:`Fingerprint` (if set) takes
        precedence for the wire-visible ``supported_groups`` list.
        """
        if not isinstance(curve_name, str) or not curve_name:
            raise TypeError("curve_name must be a non-empty str")
        with _ErrorRemapping():
            self._ctx.set_curves_list(curve_name)

    def set_session_id_context(self, ctx_id: bytes) -> None:
        """Set the session-id context used to scope server-side session reuse.

        Required for the combination *server-side TLS + client certificate
        authentication + resumption* - without it BoringSSL refuses to resume
        sessions that involved a peer certificate. Up to 32 bytes; matches
        :meth:`ssl.SSLContext.set_session_id_context`.
        """
        if not isinstance(ctx_id, (bytes, bytearray, memoryview)):
            raise TypeError("session id context must be bytes-like")
        with _ErrorRemapping():
            self._ctx.set_session_id_context(bytes(ctx_id))

    @property
    def num_tickets(self) -> int:
        """Server-side TLS 1.3 session ticket count (default ``2``).

        Setter mirrors :attr:`ssl.SSLContext.num_tickets` (CPython 3.8+).
        Reading on a client context is allowed but the value is not used.
        """
        return self._ctx.num_tickets()

    @num_tickets.setter
    def num_tickets(self, n: int) -> None:
        if not isinstance(n, int) or n < 0:
            raise ValueError("num_tickets must be a non-negative int")
        with _ErrorRemapping():
            self._ctx.set_num_tickets(n)

    def load_dh_params(self, dhfile: str | os.PathLike[str]) -> None:
        """**Unsupported.** BoringSSL removed finite-field Diffie-Hellman.

        Raised :class:`SSLError` rather than silently no-op'ing so callers
        port their configuration to ECDHE explicitly. Use
        :meth:`set_ecdh_curve` instead.
        """
        raise SSLError(
            "load_dh_params() is unsupported: BoringSSL removed finite-field "
            "DH ciphers. Use set_ecdh_curve(curve_name) to constrain ECDHE."
        )

    def set_servername_callback(self, callback: Any) -> None:
        """Install a server-side SNI dispatch callback.

        Mirrors :meth:`ssl.SSLContext.set_servername_callback`. Server-side
        only; client contexts raise :class:`ValueError`.

        The callback is invoked once per ClientHello as
        ``callback(sslobj, server_name, ssl_context)`` where:

        * ``sslobj`` exposes a read-only :attr:`server_hostname` and a
          read/write :attr:`context` property. Assigning to
          ``sslobj.context`` swaps the in-flight handshake onto the new
          :class:`SSLContext`'s certificate chain, verify mode, ALPN
          preference list, and TLS 1.3 cipher selection (BoringSSL handles
          the underlying ``SSL_CTX`` refcount).
        * ``server_name`` is the SNI string the client sent, or ``None``
          if the ClientHello had no SNI extension or an empty one.
        * ``ssl_context`` is this :class:`SSLContext` (the one the
          :class:`SSLObject` was created with).

        The callback should return either ``None`` (continue the handshake)
        or an ``int`` TLS alert code (abort the handshake with that alert,
        typically :data:`ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME`). Any
        exception raised inside the callback is printed to stderr and the
        handshake is aborted with ``internal_error``.

        Passing ``callback=None`` clears any previously installed callback.
        """
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable or None")
        if callback is not None and not self._server_side:
            raise ValueError("set_servername_callback is only valid on server contexts")
        if callback is None:
            self._ctx.set_sni_callback(None)
            self._sni_callback = None
            return

        ctx_self = self

        def _dispatch(view: Any, server_name: str | None) -> Any:
            sslobj_adapter = _SNISslObj(view, ctx_self)
            return callback(sslobj_adapter, server_name, ctx_self)

        self._ctx.set_sni_callback(_dispatch)
        # Keep a Python reference to the wrapper so the Rust side's `Py<PyAny>`
        # stays alive even if the caller's `callback` variable goes out of
        # scope. (Rust holds its own reference too; this is belt-and-braces.)
        self._sni_callback = _dispatch

    def set_fingerprint(self, fp: str | Fingerprint | None) -> None:
        if fp is None:
            with _ErrorRemapping():
                self._ctx.set_fingerprint(None)
            self._fp_py = None
            return
        if isinstance(fp, str):
            fp = Fingerprint.from_preset(fp)
        if not isinstance(fp, Fingerprint):
            raise TypeError(f"expected Fingerprint or preset name, got {type(fp).__name__}")
        # The Rust binding accepts `_utls.Fingerprint` directly. May raise on
        # server contexts (servers do not send a ClientHello).
        with _ErrorRemapping():
            self._ctx.set_fingerprint(fp._handle)
        # Cache so `fingerprint` / `http_header_for_fingerprint()` return the
        # original Python wrapper (with headers) rather than a reconstructed
        # view of the Rust-side handle (which has no headers).
        self._fp_py = fp

    @property
    def fingerprint(self) -> Fingerprint | None:
        # Prefer the cached Python wrapper - it carries the HTTP-header bundle
        # the Rust core doesn't know about. Fall back to wrapping the live
        # handle (e.g. after a fork via `set_ech_configs` that didn't
        # carry the cache forward, though that path does carry it forward).
        if self._fp_py is not None:
            return self._fp_py
        h = self._ctx.fingerprint()
        return Fingerprint._wrap(h) if h is not None else None

    def http_header_for_fingerprint(self) -> dict[str, str]:
        """Return the per-request HTTP headers paired with the active fingerprint.

        The returned ``dict`` is a fresh copy preserving Chrome's on-the-wire
        insertion order. See :attr:`Fingerprint.http_headers` for the exact
        contract (which headers are included, which are deliberately omitted,
        and why the order matters for impersonation).

        Raises :class:`ValueError` when no fingerprint has been applied to
        this context, since asking for "the headers" without a fingerprint
        is unambiguously a caller bug - there is no sensible default header
        set we could fabricate.
        """
        if self._fp_py is None:
            raise ValueError(
                "no fingerprint set on this SSLContext; call "
                "set_fingerprint(<preset name or Fingerprint>) first"
            )
        return self._fp_py.http_headers

    def set_ech_configs(self, ech_config_list: bytes | None) -> SSLContext:
        """Return a **new** :class:`SSLContext` carrying the supplied ECH
        ``ECHConfigList`` (or ``None`` to clear it on the clone).

        This method is **non-mutating**. The returned context shares the
        underlying ``SSL_CTX`` (and so the trust store, loaded certificates,
        and other ``SSL_CTX``-level configuration) with ``self`` via
        ``SSL_CTX_up_ref``; the per-wrapper Rust state (fingerprint, verify
        mode, hostname check, TLS version bounds) is snapshot at clone time.

        Rationale: ECH configs are **peer-specific** - each origin publishes
        its own config in a DNS HTTPS RR. Storing one on a shared, long-lived
        context would couple that context to a single peer. The supported
        pattern is to keep one configured base context and fork a cheap
        per-peer copy carrying that peer's ECH bytes::

            base = utls.SSLContext()
            base.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
            base.set_fingerprint("chrome:stable")

            # per-connection:
            ech_bytes = fetch_https_rr("example.com").params["ech"]
            ctx = base.set_ech_configs(ech_bytes)
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname="example.com")

        ``utls`` does not perform the DNS HTTPS RR lookup; the caller fetches
        the ``ech=`` bytes (e.g. via ``dnspython``'s ``HTTPS`` rdata).

        The signature matches ``rtls.SSLContext.set_ech_configs``, which
        urllib3.future probes with ``hasattr(ctx, "set_ech_configs")``.
        """
        if ech_config_list is not None and not isinstance(
            ech_config_list, (bytes, bytearray, memoryview)
        ):
            raise TypeError(
                f"ech_config_list must be bytes-like or None, got {type(ech_config_list).__name__}"
            )
        ech_bytes = bytes(ech_config_list) if ech_config_list is not None else None
        new_inner = self._ctx.set_ech_configs(ech_bytes)
        clone = SSLContext.__new__(SSLContext)
        # Preserve every Python-side attribute the base context carries so the
        # clone is observationally indistinguishable for everything except ECH.
        clone.__dict__.update(self.__dict__)
        clone._ctx = new_inner
        return clone

    def wrap_bio(
        self,
        incoming: Any,
        outgoing: Any,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: SSLSession | None = None,
    ) -> SSLObject:
        # `server_side` must agree with the context's protocol: a context
        # constructed with PROTOCOL_TLS_SERVER cannot be used to drive a
        # client handshake, and vice versa. This mirrors stdlib behaviour
        # (the stdlib raises ``ValueError: Cannot set server_side=True ...``
        # when the SSL_CTX was made with PROTOCOL_TLS_CLIENT).
        if server_side and not self._server_side:
            raise ValueError("server_side=True requires SSLContext(PROTOCOL_TLS_SERVER)")
        if not server_side and self._server_side:
            raise ValueError(
                "this SSLContext was created with PROTOCOL_TLS_SERVER; "
                "pass server_side=True or use a client context"
            )
        if server_side and server_hostname is not None:
            raise ValueError("server_hostname must be None for server-side SSLObject")

        # Two regimes (see `SSLObject` docstring):
        #
        #   * Native - both BIOs are `utls.MemoryBIO`: the SSL engine reads
        #     and writes those Rust-backed buffers directly.
        #   * Adapted - one or both BIOs are `ssl.MemoryBIO` (the stdlib type,
        #     used by `asyncio.sslproto`). `ssl.MemoryBIO` is a CPython C type
        #     and is not subclassable, so we cannot make our `MemoryBIO` an
        #     `isinstance` of it nor share a buffer with it. Instead we
        #     allocate a private pair of Rust BIOs that the SSL engine
        #     consumes/produces, and the resulting `SSLObject` pumps bytes
        #     between the caller's stdlib BIOs and the private Rust BIOs
        #     around every operation.
        for label, bio in (("incoming", incoming), ("outgoing", outgoing)):
            if not isinstance(bio, (MemoryBIO, _stdlib_ssl.MemoryBIO)):
                raise TypeError(
                    f"{label} must be an utls.MemoryBIO or ssl.MemoryBIO "
                    f"instance, got {type(bio).__name__}"
                )

        needs_pump = not (isinstance(incoming, MemoryBIO) and isinstance(outgoing, MemoryBIO))
        if needs_pump:
            rust_in = MemoryBIO()
            rust_out = MemoryBIO()
            engine_in, engine_out = rust_in, rust_out
        else:
            rust_in = rust_out = None  # type: ignore[assignment]
            engine_in, engine_out = incoming, outgoing

        with _ErrorRemapping():
            conn = self._ctx.wrap_bio(
                engine_in._bio,
                engine_out._bio,
                server_hostname,
                session._session if session is not None else None,
            )
        return SSLObject(
            conn,
            self,
            incoming,
            outgoing,
            server_hostname,
            session,
            rust_incoming=rust_in,
            rust_outgoing=rust_out,
        )

    def wrap_socket(
        self,
        sock: Any,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: SSLSession | None = None,
    ) -> Any:
        if server_side and not self._server_side:
            raise ValueError("server_side=True requires SSLContext(PROTOCOL_TLS_SERVER)")
        if not server_side and self._server_side:
            raise ValueError(
                "this SSLContext was created with PROTOCOL_TLS_SERVER; "
                "pass server_side=True or use a client context"
            )
        # Imported lazily to avoid a circular import via _socket.
        from ._socket import SSLSocket

        return SSLSocket(
            sock=sock,
            context=self,
            server_side=server_side,
            server_hostname=server_hostname,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            session=session,
        )


def create_default_context(
    purpose: Purpose = Purpose.SERVER_AUTH,
    *,
    cafile: str | os.PathLike[str] | None = None,
    capath: str | os.PathLike[str] | None = None,
    cadata: str | bytes | None = None,
) -> SSLContext:
    """Build a sensibly-defaulted client SSLContext.

    Mirrors :func:`ssl.create_default_context`. When no explicit CA material
    is provided, the OS default trust store is loaded.
    """
    ctx = SSLContext(PROTOCOL_TLS_CLIENT)
    # check_hostname / verify_mode are already set to safe defaults by the
    # underlying Rust context; setting them explicitly here keeps the
    # public surface symmetric with stdlib.
    ctx.check_hostname = True
    ctx.verify_mode = CERT_REQUIRED
    ctx.minimum_version = TLSVersion.TLSv1_2
    ctx.maximum_version = TLSVersion.TLSv1_3
    if cafile is None and capath is None and cadata is None:
        ctx.load_default_certs(purpose)
    else:
        ctx.load_verify_locations(cafile=cafile, capath=capath, cadata=cadata)
    # Match stdlib: no default ALPN. Callers who want HTTP/2 must opt in
    # via `ctx.set_alpn_protocols([...])`.
    return ctx


def _coerce_pem(source: str | bytes | os.PathLike[str], *, label: str) -> bytes:
    """Coerce a path-or-PEM argument into raw PEM bytes.

    Polymorphism mirrors what most secret-store integrations want:

    * ``bytes`` / ``bytearray`` / ``memoryview`` - already PEM, returned as-is.
    * ``str`` containing ``-----BEGIN`` - inline PEM, ASCII-encoded.
    * ``str`` / ``os.PathLike`` otherwise - filesystem path, opened and read.

    ``label`` is interpolated into the ``TypeError`` raised when the input
    type is none of the above (``certfile`` / ``keyfile`` / ...).
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    if isinstance(source, str):
        if "-----BEGIN" in source:
            return source.encode("ascii")
        with open(source, "rb") as f:
            return f.read()
    # os.PathLike fallback - covers pathlib.Path and anything implementing
    # __fspath__. fspath() returns str (or bytes; we treat bytes as a path
    # too, never inline PEM, since that's what __fspath__ is *for*).
    try:
        fspath = os.fspath(source)
    except TypeError as exc:
        raise TypeError(
            f"{label} must be str, bytes, or os.PathLike, got {type(source).__name__}"
        ) from exc
    if isinstance(fspath, bytes):
        with open(fspath, "rb") as f:
            return f.read()
    with open(fspath, "rb") as f:
        return f.read()


def _iter_pem_certs(data: bytes) -> Iterable[bytes]:
    """Yield DER blobs from a concatenated PEM byte string."""
    import base64

    BEGIN = b"-----BEGIN CERTIFICATE-----"
    END = b"-----END CERTIFICATE-----"
    start = 0
    while True:
        b = data.find(BEGIN, start)
        if b == -1:
            return
        e = data.find(END, b)
        if e == -1:
            raise SSLError("malformed PEM: BEGIN without matching END")
        body = data[b + len(BEGIN) : e].replace(b"\r", b"").replace(b"\n", b"")
        try:
            yield base64.b64decode(body, validate=True)
        except Exception as ex:
            raise SSLError(f"malformed PEM body: {ex}") from ex
        start = e + len(END)

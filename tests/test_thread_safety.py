from __future__ import annotations

import socket
import ssl as _stdlib_ssl
import threading
from concurrent.futures import ThreadPoolExecutor

import trustme

import utls




def _run_echo_server(host: str, server_ctx: _stdlib_ssl.SSLContext, payload_size: int = 0):
    """Plain stdlib TLS echo server. Optionally pre-sends `payload_size`
    bytes so the client can spend real time inside `read`."""
    sock = socket.socket()
    sock.bind((host, 0))
    sock.listen(1)
    sock.settimeout(10)
    port = sock.getsockname()[1]

    def serve() -> None:
        try:
            client, _addr = sock.accept()
            with server_ctx.wrap_socket(client, server_side=True) as tls:
                if payload_size:
                    try:
                        tls.sendall(b"X" * payload_size)
                    except OSError:
                        pass
                # Echo loop until peer goes away
                try:
                    while True:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        tls.sendall(chunk)
                except OSError:
                    pass
        except Exception:
            pass
        finally:
            sock.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, t


def _make_pair():
    """Spin up a CA, server context, and utls client context."""
    ca = trustme.CA()
    cert = ca.issue_cert("localhost")
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ctx)
    client_ctx = utls.create_default_context()
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode("ascii"))
    return server_ctx, client_ctx




def test_sslcontext_methods_callable_from_other_thread():
    """`SSLContext` is created on the main thread but its methods are
    routinely called from worker threads (thread executors, asyncio's
    default loop policy on Windows, urllib3 connection pools). Pre-fix
    this panicked with ``Pyclass 'Context' is unsendable and cannot be
    accessed by other threads``.
    """
    ctx = utls.create_default_context()

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            # Touch every public getter/setter we can without needing a peer.
            assert ctx.verify_mode == _stdlib_ssl.CERT_REQUIRED
            assert ctx.check_hostname is True
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            assert ctx.protocol == _stdlib_ssl.PROTOCOL_TLS_CLIENT
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=5)
    assert not errors, f"cross-thread access raised: {errors!r}"


def test_memorybio_usable_from_other_thread():
    """Same for `MemoryBIO`. asyncio's SSLProtocol writes to one BIO from
    the loop thread but may be read from a transport callback on another."""
    bio = utls.MemoryBIO()
    bio.write(b"hello")

    captured: list[bytes] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            captured.append(bio.read(-1))
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=5)
    assert not errors, f"cross-thread BIO access raised: {errors!r}"
    assert captured == [b"hello"]


def test_sslsocket_handshake_on_worker_thread():
    """End-to-end: the `Connection` handle is created on the main thread
    (`wrap_socket` returns from there) but the handshake runs in a worker.
    Pre-fix this would panic the worker thread before the handshake ever
    started."""
    server_ctx, client_ctx = _make_pair()
    port, server_thread = _run_echo_server("127.0.0.1", server_ctx)

    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    sslobj = client_ctx.wrap_socket(raw, server_hostname="localhost", do_handshake_on_connect=False)

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            sslobj.do_handshake()
            sslobj.sendall(b"ping")
            assert sslobj.recv(4) == b"ping"
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=10)

    try:
        sslobj.close()
    except OSError:
        pass
    raw.close()
    server_thread.join(timeout=5)

    assert not errors, f"worker-thread handshake raised: {errors!r}"




def test_concurrent_reader_and_closer_no_already_borrowed():
    """Race a reader against a closer on the same `SSLSocket`. The reader
    spends time inside `py.detach()` on `recv`; meanwhile the closer
    issues `shutdown`/`close` which also enters the engine. Pre-fix on
    `&mut self`-based bindings this reliably surfaced
    ``RuntimeError: Already borrowed`` on a non-trivial percentage of
    runs. The current `&self` + `Mutex` shape should serialise cleanly.
    """
    server_ctx, client_ctx = _make_pair()
    # Big preloaded payload so the reader stays inside the engine for a while.
    port, server_thread = _run_echo_server("127.0.0.1", server_ctx, payload_size=1 << 20)

    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    sslobj = client_ctx.wrap_socket(raw, server_hostname="localhost")

    fatal: list[BaseException] = []

    def reader() -> None:
        try:
            while True:
                chunk = sslobj.recv(1)  # tiny reads -> max GIL-release churn
                if not chunk:
                    break
        except RuntimeError as exc:  # this is the only failure mode we care about
            if "Already borrowed" in str(exc) or "unsendable" in str(exc):
                fatal.append(exc)
        except (OSError, _stdlib_ssl.SSLError, utls.SSLError):
            pass  # connection teardown is fine

    def closer() -> None:
        import time
        time.sleep(0.01)  # let reader enter py.detach()
        try:
            sslobj.close()
        except RuntimeError as exc:
            if "Already borrowed" in str(exc) or "unsendable" in str(exc):
                fatal.append(exc)
        except (OSError, _stdlib_ssl.SSLError, utls.SSLError):
            pass

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(reader)
        f2 = pool.submit(closer)
        f1.result(timeout=15)
        f2.result(timeout=15)

    raw.close()
    server_thread.join(timeout=5)

    assert not fatal, f"PyO3 thread-safety panic: {fatal!r}"


def test_parallel_handshakes_on_shared_context():
    """The same `SSLContext` is shared across many connections. Each
    handshake runs on its own worker. This stresses both cross-thread
    access *and* concurrent locking inside `wrap_socket`."""
    server_ctx, client_ctx = _make_pair()

    fatal: list[BaseException] = []
    N = 8

    def one_handshake() -> None:
        try:
            port, server_thread = _run_echo_server("127.0.0.1", server_ctx)
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            try:
                sslobj = client_ctx.wrap_socket(raw, server_hostname="localhost")
                sslobj.sendall(b"x")
                assert sslobj.recv(1) == b"x"
                sslobj.close()
            finally:
                raw.close()
                server_thread.join(timeout=5)
        except RuntimeError as exc:
            if "Already borrowed" in str(exc) or "unsendable" in str(exc):
                fatal.append(exc)

    with ThreadPoolExecutor(max_workers=N) as pool:
        futures = [pool.submit(one_handshake) for _ in range(N)]
        for f in futures:
            f.result(timeout=30)

    assert not fatal, f"PyO3 thread-safety panic under parallel load: {fatal!r}"

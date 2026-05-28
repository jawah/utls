from __future__ import annotations

import os
import socket
import ssl
import tempfile
import threading

import pytest
import trustme

import utls


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


def _materialise(cert: trustme.LeafCert) -> tuple[str, str]:
    """Write a trustme leaf cert + key to a tmpdir; return (cert_path, key_path).
    The tmpdir is leaked on purpose (cleaned on process exit) so the paths
    stay valid for the lifetime of the test module.
    """
    td = tempfile.mkdtemp(prefix="utls-sni-")
    cpath = os.path.join(td, "cert.pem")
    kpath = os.path.join(td, "key.pem")
    cert.cert_chain_pems[0].write_to_path(cpath)
    cert.private_key_pem.write_to_path(kpath)
    return cpath, kpath


@pytest.fixture(scope="module")
def alpha_paths(ca: trustme.CA) -> tuple[str, str]:
    return _materialise(ca.issue_cert("alpha.test", "127.0.0.1"))


@pytest.fixture(scope="module")
def beta_paths(ca: trustme.CA) -> tuple[str, str]:
    return _materialise(ca.issue_cert("beta.test", "127.0.0.1"))


@pytest.fixture(scope="module")
def ca_pem_path(ca: trustme.CA) -> str:
    td = tempfile.mkdtemp(prefix="utls-sni-ca-")
    p = os.path.join(td, "ca.pem")
    ca.cert_pem.write_to_path(p)
    return p


def _make_server_ctx(cert_paths: tuple[str, str]) -> utls.SSLContext:
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_paths[0], cert_paths[1])
    return ctx


def _make_client_ctx(ca_pem: str) -> ssl.SSLContext:
    sctx = ssl.create_default_context()
    sctx.load_verify_locations(ca_pem)
    return sctx


def _run_one_handshake(
    server_ctx: utls.SSLContext,
    client_ctx: ssl.SSLContext,
    server_hostname: str,
    *,
    expect_handshake_failure: bool = False,
) -> dict:
    """Drive a single stdlib-client <-> utls-server handshake.

    Returns a dict with `client_err` populated if `expect_handshake_failure`.
    """
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    box: dict = {}

    def server_thread() -> None:
        try:
            conn, _ = lsock.accept()
            ssock = server_ctx.wrap_socket(conn, server_side=True)
            try:
                ssock.recv(4096)
                ssock.sendall(b"ok")
            finally:
                ssock.close()
        except Exception as e:
            box["server_err"] = e

    th = threading.Thread(target=server_thread)
    th.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as cs:
            try:
                csock = client_ctx.wrap_socket(cs, server_hostname=server_hostname)
            except (ssl.SSLError, OSError) as e:
                box["client_err"] = e
            else:
                try:
                    box["peer_cert"] = csock.getpeercert()
                    csock.sendall(b"hi")
                    box["client_recv"] = csock.recv(4096)
                finally:
                    csock.close()
    finally:
        th.join(timeout=5)
        lsock.close()
    if expect_handshake_failure:
        assert "client_err" in box, f"expected handshake failure, got {box!r}"
    else:
        assert "client_err" not in box, f"unexpected handshake failure: {box.get('client_err')!r}"
    return box


def test_sni_swap_selects_per_hostname(
    alpha_paths, beta_paths, ca_pem_path
):
    """Callback swaps `sslobj.context` to pick the right cert per SNI."""
    alpha_ctx = _make_server_ctx(alpha_paths)
    beta_ctx = _make_server_ctx(beta_paths)
    # The "default" context the listener is bound to also loads alpha so
    # there's a valid cert if the callback decides to do nothing.
    default_ctx = _make_server_ctx(alpha_paths)

    seen: list[str | None] = []

    def cb(sslobj, server_name, ssl_ctx):
        seen.append(server_name)
        # Exercise the read-only adapter surface stdlib callers rely on:
        # both the live SNI-string accessor and the current-context getter.
        assert sslobj.server_hostname == server_name
        assert sslobj.context is default_ctx
        # Setter type-check fires before the underlying swap_context call.
        with pytest.raises(TypeError, match="utls.SSLContext"):
            sslobj.context = "not a context"
        if server_name == "beta.test":
            sslobj.context = beta_ctx
        elif server_name == "alpha.test":
            sslobj.context = alpha_ctx
        return None

    default_ctx.set_servername_callback(cb)

    client_ctx = _make_client_ctx(ca_pem_path)

    # Beta path: callback swaps -> beta cert presented -> client verifies
    # against the same CA. The cert CN must be beta.test for verification.
    box = _run_one_handshake(default_ctx, client_ctx, "beta.test")
    assert box["client_recv"] == b"ok"
    # SNI string the callback observed.
    assert "beta.test" in seen

    # Alpha path: same callback, picks alpha. Use a fresh client ctx so the
    # session cache from the previous run cannot mask a fingerprint mismatch.
    box = _run_one_handshake(default_ctx, _make_client_ctx(ca_pem_path), "alpha.test")
    assert box["client_recv"] == b"ok"
    assert "alpha.test" in seen


def test_sni_callback_returning_alert_aborts(alpha_paths, ca_pem_path):
    """Returning an int alert from the callback fails the handshake."""
    ctx = _make_server_ctx(alpha_paths)

    def cb(sslobj, server_name, ssl_ctx):
        # 112 = unrecognized_name (RFC 6066 §3).
        return 112

    ctx.set_servername_callback(cb)
    client_ctx = _make_client_ctx(ca_pem_path)
    box = _run_one_handshake(
        ctx, client_ctx, "alpha.test", expect_handshake_failure=True
    )
    err = box["client_err"]
    assert isinstance(err, ssl.SSLError)
    # The alert text varies across OpenSSL versions; just check it's a TLS
    # alert (not e.g. a connection reset).
    msg = str(err).lower()
    assert "alert" in msg or "unrecognized" in msg or "handshake" in msg


def test_sni_callback_exception_aborts(alpha_paths, ca_pem_path):
    """An exception inside the callback fails the handshake."""
    ctx = _make_server_ctx(alpha_paths)

    def cb(sslobj, server_name, ssl_ctx):
        raise RuntimeError("boom from cb")

    ctx.set_servername_callback(cb)
    client_ctx = _make_client_ctx(ca_pem_path)
    box = _run_one_handshake(
        ctx, client_ctx, "alpha.test", expect_handshake_failure=True
    )
    assert isinstance(box["client_err"], (ssl.SSLError, OSError))


def test_sni_clear_callback(alpha_paths, ca_pem_path):
    """Passing None clears any previously installed callback."""
    ctx = _make_server_ctx(alpha_paths)
    calls: list[str | None] = []
    ctx.set_servername_callback(lambda s, n, c: calls.append(n))
    ctx.set_servername_callback(None)
    client_ctx = _make_client_ctx(ca_pem_path)
    box = _run_one_handshake(ctx, client_ctx, "alpha.test")
    assert box["client_recv"] == b"ok"
    # Callback was cleared -> never invoked.
    assert calls == []


def test_sni_rejects_non_callable():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    with pytest.raises(TypeError):
        ctx.set_servername_callback(42)


def test_sni_client_context_rejects_callback():
    """set_servername_callback is server-side only."""
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(ValueError):
        ctx.set_servername_callback(lambda s, n, c: None)


def test_sni_view_invalidated_outside_callback(alpha_paths, beta_paths, ca_pem_path):
    """Holding onto the view past the callback's return raises on use."""
    ctx = _make_server_ctx(alpha_paths)
    beta_ctx = _make_server_ctx(beta_paths)
    leaked: list = []

    def cb(sslobj, server_name, ssl_ctx):
        leaked.append(sslobj)
        return None

    ctx.set_servername_callback(cb)
    client_ctx = _make_client_ctx(ca_pem_path)
    _run_one_handshake(ctx, client_ctx, "alpha.test")
    assert leaked
    # Touching the view post-callback should fail; we tunnel through the
    # underlying _utls.SniHandshakeView since that's where the invalidation
    # lives. The high-level adapter's setter delegates to it.
    with pytest.raises(RuntimeError):
        leaked[0].context = beta_ctx

from __future__ import annotations

import socket
import ssl
import threading

import pytest
import trustme

import utls



@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="module")
def server_cert(ca: trustme.CA):
    return ca.issue_cert("localhost", "127.0.0.1")


@pytest.fixture(scope="module")
def client_cert(ca: trustme.CA):
    return ca.issue_cert("client@example.com")


def _make_server_ctx(server_cert) -> utls.SSLContext:
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    # trustme exposes PEM via cert_chain_pems + private_key_pem
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "cert.pem")
        kpath = os.path.join(td, "key.pem")
        server_cert.cert_chain_pems[0].write_to_path(cpath)
        server_cert.private_key_pem.write_to_path(kpath)
        ctx.load_cert_chain(cpath, kpath)
    return ctx


def _make_client_ctx(ca: trustme.CA) -> ssl.SSLContext:
    sctx = ssl.create_default_context()
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        capath = os.path.join(td, "ca.pem")
        ca.cert_pem.write_to_path(capath)
        sctx.load_verify_locations(capath)
    return sctx


def _run_pair(server_ctx: utls.SSLContext, client_ctx: ssl.SSLContext,
              *, server_side_extra=None, client_send: bytes = b"ping",
              server_reply: bytes = b"pong"):
    """Run a single TLS exchange: stdlib client <-> utls server.

    Returns (client_sslsock, server_sslobj, server_recv, client_recv).
    """
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    box = {}

    def server_thread():
        conn, _ = lsock.accept()
        ssock = server_ctx.wrap_socket(conn, server_side=True)
        if server_side_extra:
            server_side_extra(ssock)
        data = ssock.recv(4096)
        ssock.sendall(server_reply)
        box["server_sock"] = ssock
        box["server_recv"] = data

    th = threading.Thread(target=server_thread)
    th.start()
    try:
        with socket.create_connection(("127.0.0.1", port)) as cs:
            csock = client_ctx.wrap_socket(cs, server_hostname="localhost")
            csock.sendall(client_send)
            reply = csock.recv(4096)
            box["client_sock"] = csock
            box["client_recv"] = reply
    finally:
        th.join(timeout=5)
        lsock.close()
    return box



def test_basic_handshake(ca, server_cert):
    """utls server completes a handshake with the stdlib client and exchanges
    a single record successfully."""
    sctx = _make_server_ctx(server_cert)
    cctx = _make_client_ctx(ca)
    box = _run_pair(sctx, cctx)
    assert box["server_recv"] == b"ping"
    assert box["client_recv"] == b"pong"


def test_alpn_server_selects_first_preference(ca, server_cert):
    """Server preference order wins ALPN selection (RFC 7301 §3.2). utls
    server's policy: walk *our* preference list, pick first that appears in
    peer's offer."""
    sctx = _make_server_ctx(server_cert)
    sctx.set_alpn_protocols(["h2", "http/1.1"])
    cctx = _make_client_ctx(ca)
    cctx.set_alpn_protocols(["http/1.1", "h2"])
    box = _run_pair(sctx, cctx)
    assert box["client_sock"].selected_alpn_protocol() == "h2"


def test_mtls_required_with_client_cert(ca, server_cert, client_cert):
    """CERT_REQUIRED: client presents a cert chained to CA -> handshake OK
    and `getpeercert()` server-side surfaces the client identity."""
    sctx = _make_server_ctx(server_cert)
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        capath = os.path.join(td, "ca.pem")
        ca.cert_pem.write_to_path(capath)
        sctx.load_verify_locations(capath)
    sctx.verify_mode = utls.CERT_REQUIRED

    cctx = _make_client_ctx(ca)
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "cli.pem")
        kpath = os.path.join(td, "cli.key")
        client_cert.cert_chain_pems[0].write_to_path(cpath)
        client_cert.private_key_pem.write_to_path(kpath)
        cctx.load_cert_chain(cpath, kpath)

        def grab(ssock):
            ssock._got_peer = ssock.getpeercert()  # type: ignore[attr-defined]

        box = _run_pair(sctx, cctx, server_side_extra=grab)
    peer = box["server_sock"]._got_peer
    # trustme client cert has email SAN
    assert peer is not None
    # subjectAltName must include the email we issued for
    sans = peer.get("subjectAltName", ())
    assert any("client@example.com" in val for _, val in sans), peer


def test_mtls_required_no_client_cert_fails(ca, server_cert):
    """CERT_REQUIRED with no client cert -> handshake must fail."""
    sctx = _make_server_ctx(server_cert)
    sctx.verify_mode = utls.CERT_REQUIRED
    # need a CA loaded to even ask for a cert
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        capath = os.path.join(td, "ca.pem")
        ca.cert_pem.write_to_path(capath)
        sctx.load_verify_locations(capath)

    cctx = _make_client_ctx(ca)
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    err_box = {}

    def server_thread():
        conn = None
        try:
            conn, _ = lsock.accept()
            ssock = sctx.wrap_socket(conn, server_side=True)
            ssock.recv(1)
        except utls.SSLError as e:
            err_box["err"] = e
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    th = threading.Thread(target=server_thread)
    th.start()
    try:
        with socket.create_connection(("127.0.0.1", port)) as cs:
            cs.settimeout(3.0)
            client_ok = False
            try:
                csock = cctx.wrap_socket(cs, server_hostname="localhost")
                csock.sendall(b"x")
                data = csock.recv(1)
                # If we got here without exception, the only acceptable
                # outcome is EOF (server closed without responding).
                client_ok = (data == b"")
            except (ssl.SSLError, OSError):
                client_ok = True
            assert client_ok, "client should have failed or seen EOF"
    finally:
        th.join(timeout=5)
        lsock.close()
    assert "err" in err_box


def test_set_fingerprint_rejected_on_server(server_cert):
    """`set_fingerprint` is meaningless server-side (server doesn't send a
    ClientHello). Must raise rather than silently no-op."""
    sctx = _make_server_ctx(server_cert)
    with pytest.raises((utls.SSLError, ValueError, TypeError)):
        sctx.set_fingerprint("chrome:131")


def test_load_dh_params_raises(server_cert):
    """BoringSSL removed finite-field DH; we surface this as SSLError."""
    sctx = _make_server_ctx(server_cert)
    with pytest.raises(utls.SSLError):
        sctx.load_dh_params("/nonexistent/dh.pem")


def test_set_ecdh_curve_accepts_known(server_cert):
    """`set_ecdh_curve('prime256v1')` and colon-lists must succeed; an
    unknown curve must error."""
    sctx = _make_server_ctx(server_cert)
    sctx.set_ecdh_curve("prime256v1")
    sctx.set_ecdh_curve("X25519:prime256v1")
    with pytest.raises((utls.SSLError, ValueError)):
        sctx.set_ecdh_curve("not_a_real_curve_xyz")


def test_session_id_context(server_cert):
    """`set_session_id_context` accepts up to 32 bytes; rejects longer."""
    sctx = _make_server_ctx(server_cert)
    sctx.set_session_id_context(b"utls-test")
    with pytest.raises((utls.SSLError, ValueError)):
        sctx.set_session_id_context(b"x" * 33)


def test_num_tickets_roundtrip(server_cert):
    """`num_tickets` defaults to 2 (BoringSSL default) and is settable."""
    sctx = _make_server_ctx(server_cert)
    assert sctx.num_tickets == 2
    sctx.num_tickets = 0
    assert sctx.num_tickets == 0
    sctx.num_tickets = 4
    assert sctx.num_tickets == 4


def test_server_side_property(server_cert):
    sctx = _make_server_ctx(server_cert)
    assert sctx.server_side is True
    cctx = utls.create_default_context()
    assert cctx.server_side is False


def test_protocol_server_side_mismatch():
    """`wrap_socket(server_side=False)` on a server context must error."""
    sctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    s = socket.socket()
    try:
        with pytest.raises(ValueError):
            sctx.wrap_socket(s, server_side=False, do_handshake_on_connect=False)
    finally:
        s.close()

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


@pytest.fixture(scope="module")
def server_cert(ca: trustme.CA):
    return ca.issue_cert("localhost", "127.0.0.1")


def _server_ctx(server_cert) -> utls.SSLContext:
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as td:
        c = os.path.join(td, "cert.pem")
        k = os.path.join(td, "key.pem")
        server_cert.cert_chain_pems[0].write_to_path(c)
        server_cert.private_key_pem.write_to_path(k)
        ctx.load_cert_chain(c, k)
    return ctx


def _client_ctx(ca: trustme.CA) -> ssl.SSLContext:
    sctx = ssl.create_default_context()
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "ca.pem")
        ca.cert_pem.write_to_path(p)
        sctx.load_verify_locations(p)
    return sctx


def _exchange(server_ctx: utls.SSLContext, client_ctx: ssl.SSLContext):
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    box = {}

    def server_thread():
        conn, _ = lsock.accept()
        ssock = server_ctx.wrap_socket(conn, server_side=True)
        box["fp"] = ssock.get_fingerprint()
        box["sni"] = ssock.server_hostname
        ssock.recv(4096)
        ssock.sendall(b"ok")
        ssock.close()

    th = threading.Thread(target=server_thread)
    th.start()
    try:
        with socket.create_connection(("127.0.0.1", port)) as cs:
            csock = client_ctx.wrap_socket(cs, server_hostname="localhost")
            csock.sendall(b"hi")
            csock.recv(4096)
    finally:
        th.join(timeout=5)
        lsock.close()
    return box



def test_server_get_fingerprint_basic_shape(ca, server_cert):
    """`SSLObject.get_fingerprint()` on a server-side connection returns a
    :class:`Fingerprint` whose JA4 has the canonical
    ``<proto><tls_ver><sni>...`` shape (10-char prefix, then `_`)."""
    box = _exchange(_server_ctx(server_cert), _client_ctx(ca))
    fp = box["fp"]
    assert isinstance(fp, utls.Fingerprint), repr(fp)
    ja4 = fp.ja4_hash
    # JA4 format: "t13d_..._..." - fixed 10-char prefix with two '_' tail.
    assert isinstance(ja4, str) and ja4.count("_") == 2, ja4
    # stdlib client sends SNI; JA4 'd' = "with SNI"
    assert ja4[0] == "t" and ja4[3] == "d", ja4


def test_server_observes_client_sni(ca, server_cert):
    """`server_hostname` on a server-side SSLObject must mirror the peer's
    SNI (stdlib parity: ssl.SSLSocket.server_hostname on the server side)."""
    box = _exchange(_server_ctx(server_cert), _client_ctx(ca))
    assert box["sni"] == "localhost"


def test_server_fingerprint_ja3_and_to_dict_roundtrip(ca, server_cert):
    """JA3 string + hash populated; ``to_dict()`` round-trips key fields."""
    box = _exchange(_server_ctx(server_cert), _client_ctx(ca))
    fp = box["fp"]
    ja3 = fp.ja3_string
    assert isinstance(ja3, str) and ja3.count(",") == 4, ja3
    h = fp.ja3_hash
    assert isinstance(h, str) and len(h) == 32  # md5 hex
    d = fp.to_dict()
    assert "cipher_suites" in d and isinstance(d["cipher_suites"], (list, tuple))
    assert len(d["cipher_suites"]) > 0


def test_client_get_fingerprint_echoes_configured(ca):
    """Client side: ``SSLObject.get_fingerprint()`` returns the
    :class:`Fingerprint` we configured via ``set_fingerprint``."""
    cctx = utls.create_default_context()
    fp_in = utls.Fingerprint.from_preset("chrome:131")
    cctx.set_fingerprint(fp_in)
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    obj = cctx.wrap_bio(inc, out, server_hostname="example.com")
    fp_out = obj.get_fingerprint()
    assert fp_out is fp_in  # cached identity


def test_client_get_fingerprint_none_when_unset():
    """No fingerprint configured -> ``get_fingerprint()`` returns ``None``."""
    cctx = utls.create_default_context()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    obj = cctx.wrap_bio(inc, out, server_hostname="example.com")
    assert obj.get_fingerprint() is None

from __future__ import annotations

import ssl as _stdlib_ssl

import pytest

import utls
from utls import SSLContext, SSLEOFError, SSLError, SSLWantReadError


def test_pending_grows_with_writes():
    bio = utls.MemoryBIO()
    assert bio.pending == 0
    assert not bio.eof
    n = bio.write(b"hello")
    assert n == 5
    assert bio.pending == 5


def test_read_drains_buffer():
    bio = utls.MemoryBIO()
    bio.write(b"hello world")
    chunk = bio.read(5)
    assert chunk == b"hello"
    assert bio.pending == 6
    assert bio.read(-1) == b" world"
    assert bio.pending == 0


def test_eof_only_reports_true_after_buffer_drained():
    bio = utls.MemoryBIO()
    bio.write(b"abc")
    bio.write_eof()
    assert not bio.eof, "eof must be False while bytes remain pending"
    assert bio.read(-1) == b"abc"
    assert bio.eof


def test_write_after_eof_raises():
    bio = utls.MemoryBIO()
    bio.write_eof()
    with pytest.raises(ValueError):
        bio.write(b"x")


# SSLObject (MemoryBIO-backed connection): pre-handshake getter behaviour

@pytest.fixture()
def fresh_client_obj():
    ctx = utls.create_default_context()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    return ctx, ctx.wrap_bio(inc, out, server_hostname="example.com")


def test_sslobject_pending_starts_at_zero(fresh_client_obj):
    _, obj = fresh_client_obj
    # wrap_bio alone does not start the handshake; outgoing is empty.
    assert obj.pending() == 0


@pytest.mark.parametrize("bio_class", [utls.MemoryBIO, _stdlib_ssl.MemoryBIO])
def test_sslobject_pending_ignores_handshake_ciphertext(bio_class):
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    incoming, outgoing = bio_class(), bio_class()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    with pytest.raises(SSLWantReadError):
        obj.do_handshake()
    queued = outgoing.pending
    assert queued > 0
    assert obj.pending() == 0
    assert outgoing.pending == queued


def test_sslobject_context_getter_returns_owner(fresh_client_obj):
    ctx, obj = fresh_client_obj
    assert obj.context is ctx


def test_sslobject_server_hostname_getter_returns_hostname(fresh_client_obj):
    _, obj = fresh_client_obj
    assert obj.server_hostname == "example.com"


def test_sslobject_server_hostname_none_on_anonymous_client():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # required to pass server_hostname=None
    ctx.verify_mode = utls.CERT_NONE
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=None)
    assert obj.server_hostname is None


def test_sslobject_session_is_none_before_handshake(fresh_client_obj):
    _, obj = fresh_client_obj
    assert obj.session is None


def test_sslobject_session_reused_is_false_before_handshake(fresh_client_obj):
    _, obj = fresh_client_obj
    assert obj.session_reused is False


def test_sslobject_get_unverified_chain_empty_before_handshake(fresh_client_obj):
    _, obj = fresh_client_obj
    # No peer cert yet -> stdlib returns []; we mirror that.
    assert obj.get_unverified_chain() == []


def test_sslobject_sslobj_property_self_aliases(fresh_client_obj):
    # urllib3-future relies on `ssl_object._sslobj.get_verified_chain()`
    # working when handed an SSLObject directly; the alias is just `self`.
    _, obj = fresh_client_obj
    assert obj._sslobj is obj


# Adapted-BIO regime: stdlib ssl.MemoryBIO -> rust BIO pump

@pytest.mark.parametrize("bio_class", [utls.MemoryBIO, _stdlib_ssl.MemoryBIO])
def test_handshake_rejects_transport_eof(bio_class):
    ctx = utls.create_default_context()
    inc, out = bio_class(), bio_class()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    inc.write_eof()
    with pytest.raises(SSLEOFError):
        obj.do_handshake()


def _drive(client, server, c_in, c_out, s_in, s_out):
    """Pump bytes both ways until both sides finish the handshake. Plain
    memorybio shuffle - no socket involved."""
    for _ in range(16):
        for side in (client, server):
            try:
                side.do_handshake()
            except (_stdlib_ssl.SSLWantReadError, _stdlib_ssl.SSLWantWriteError):
                pass
        d = c_out.read()
        if d:
            s_in.write(d)
        d = s_out.read()
        if d:
            c_in.write(d)


def _connected_pair(ca, cert, bio_class=utls.MemoryBIO):
    sctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    cert.configure_cert(sctx)
    cctx = utls.create_default_context()
    ca.configure_trust(cctx)
    c_in, c_out = bio_class(), bio_class()
    s_in, s_out = bio_class(), bio_class()
    cobj = cctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    sobj = sctx.wrap_bio(s_in, s_out, server_side=True)
    _drive(cobj, sobj, c_in, c_out, s_in, s_out)
    return cobj, sobj, c_in, c_out, s_in, s_out


@pytest.mark.parametrize("bio_class", [utls.MemoryBIO, _stdlib_ssl.MemoryBIO])
@pytest.mark.parametrize("server_side", [False, True])
def test_sslobject_pending_counts_only_buffered_plaintext(ca, bio_class, server_side):
    cert = ca.issue_cert("localhost")
    client, server, c_in, c_out, s_in, s_out = _connected_pair(ca, cert, bio_class)
    if server_side:
        reader, writer = server, client
        incoming, outgoing, peer_outgoing = s_in, s_out, c_out
    else:
        reader, writer = client, server
        incoming, outgoing, peer_outgoing = c_in, c_out, s_out

    writer.write(b"abcdef")
    incoming.write(peer_outgoing.read())
    queued = incoming.pending
    assert queued > 0
    # pending() must not process ciphertext, even when a complete record is queued.
    assert reader.pending() == 0
    assert incoming.pending == queued

    assert reader.read(1) == b"a"
    assert reader.pending() == 5
    assert reader.pending() == 5  # Inspecting pending data must not consume it.
    reader.write(b"outbound")
    assert outgoing.pending > 0
    assert reader.pending() == 5
    assert reader.read(2) == b"bc"
    assert reader.pending() == 3
    assert reader.read(3) == b"def"
    assert reader.pending() == 0
    assert outgoing.pending > 0


def test_sslobject_read_into_bytearray(ca):
    cert = ca.issue_cert("localhost")
    cobj, sobj, c_in, c_out, s_in, s_out = _connected_pair(ca, cert)
    sobj.write(b"hello world")
    d = s_out.read()
    if d:
        c_in.write(d)
    buf = bytearray(64)
    n = cobj.read(64, buf)
    assert n == len(b"hello world")
    assert bytes(buf[:n]) == b"hello world"


def test_sslobject_read_into_memoryview(ca):
    cert = ca.issue_cert("localhost")
    cobj, sobj, c_in, c_out, s_in, s_out = _connected_pair(ca, cert)
    sobj.write(b"abcd")
    d = s_out.read()
    if d:
        c_in.write(d)
    backing = bytearray(8)
    n = cobj.read(8, memoryview(backing))
    assert n == 4
    assert bytes(backing[:4]) == b"abcd"


def test_sslobject_read_rejects_readonly_buffer(ca):
    cert = ca.issue_cert("localhost")
    cobj, sobj, _, _, _, s_out = _connected_pair(ca, cert)
    sobj.write(b"x")
    with pytest.raises(TypeError):
        cobj.read(1, b"immutable")  # bytes are read-only


@pytest.mark.parametrize("tls_version", [_stdlib_ssl.TLSVersion.TLSv1_2, _stdlib_ssl.TLSVersion.TLSv1_3])
@pytest.mark.parametrize("bio_class", [utls.MemoryBIO, _stdlib_ssl.MemoryBIO])
@pytest.mark.parametrize("buffered", [False, True])
@pytest.mark.parametrize("payload", [b"", b"abcdef"])
@pytest.mark.parametrize("shutdown", ["clean", "clean-and-eof", "unclean", "truncated"])
def test_sslobject_read_eof(ca, tls_version, bio_class, buffered, payload, shutdown):
    sctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("localhost").configure_cert(sctx)
    sctx.minimum_version = sctx.maximum_version = tls_version
    cctx = utls.create_default_context()
    ca.configure_trust(cctx)
    c_in, c_out = bio_class(), bio_class()
    s_in, s_out = _stdlib_ssl.MemoryBIO(), _stdlib_ssl.MemoryBIO()
    client = cctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    server = sctx.wrap_bio(s_in, s_out, server_side=True)
    _drive(client, server, c_in, c_out, s_in, s_out)
    assert client.version() == tls_version.name.replace("_", ".")

    buffer = bytearray(4) if buffered else None
    with pytest.raises(SSLWantReadError):
        client.read(4, buffer)
    if payload:
        assert server.write(payload) == len(payload)
    clean = shutdown in ("clean", "clean-and-eof")
    if clean:
        with pytest.raises(_stdlib_ssl.SSLWantReadError):
            server.unwrap()
        assert s_out.pending > 0
    c_in.write(s_out.read())
    if shutdown == "truncated":
        server.write(b"incomplete record")
        c_in.write(s_out.read()[:-1])
    if shutdown != "clean":
        c_in.write_eof()

    # Return all complete application data before reporting either kind of EOF.
    received = bytearray()
    while len(received) < len(payload):
        result = client.read(4, buffer)
        assert result  # EOF before all application data would truncate it.
        received.extend(buffer[:result] if buffered else result)
    assert received == payload
    for _ in range(2):
        if buffered:
            buffer[:] = b"xxxx"
        if clean:
            assert client.read(4, buffer) == (0 if buffered else b"")
        else:
            with pytest.raises(SSLEOFError):
                client.read(4, buffer)
        if buffered:
            assert buffer == b"xxxx"


@pytest.mark.parametrize("buffered", [False, True])
@pytest.mark.parametrize("kind, error_type", [
    ("WantRead", SSLWantReadError),
    ("WantWrite", utls.SSLWantWriteError),
    ("Eof", SSLEOFError),
    ("Protocol", SSLError),
])
def test_sslobject_read_preserves_errors(fresh_client_obj, monkeypatch, buffered, kind, error_type):
    from utls import _utls

    class FailingConnection:
        def read(self, n):
            raise _utls.CoreError(kind, "read failed")

    _, obj = fresh_client_obj
    monkeypatch.setattr(obj, "_conn", FailingConnection())
    with pytest.raises(error_type, match="read failed"):
        obj.read(4, bytearray(4) if buffered else None)

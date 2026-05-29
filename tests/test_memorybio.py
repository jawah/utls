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

def test_adapted_bio_pumps_eof_into_rust_incoming():
    # Stdlib MemoryBIO triggers the "adapted" regime (separate rust BIOs
    # plus _pumping=True). do_handshake -> _pump_in -> sees inc.eof ->
    # rust_incoming.write_eof(). The handshake itself cannot proceed
    # without peer bytes, but the pump runs.
    ctx = utls.create_default_context()
    inc = _stdlib_ssl.MemoryBIO()
    out = _stdlib_ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    inc.write_eof()
    with pytest.raises((SSLError, SSLWantReadError, SSLEOFError)):
        obj.do_handshake()


def _drive(client, server, c_in, c_out, s_in, s_out):
    """Pump bytes both ways until both sides finish the handshake. Plain
    memorybio shuffle - no socket involved."""
    for _ in range(16):
        for side in (client, server):
            try:
                side.do_handshake()
            except (utls.SSLWantReadError, utls.SSLWantWriteError):
                pass
        d = c_out.read()
        if d:
            s_in.write(d)
        d = s_out.read()
        if d:
            c_in.write(d)


def _connected_pair(ca, cert):
    sctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    cert.configure_cert(sctx)
    cctx = utls.create_default_context()
    ca.configure_trust(cctx)
    c_in, c_out = utls.MemoryBIO(), utls.MemoryBIO()
    s_in, s_out = utls.MemoryBIO(), utls.MemoryBIO()
    cobj = cctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    sobj = sctx.wrap_bio(s_in, s_out, server_side=True)
    _drive(cobj, sobj, c_in, c_out, s_in, s_out)
    return cobj, sobj, c_in, c_out, s_in, s_out


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

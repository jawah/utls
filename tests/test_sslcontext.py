"""SSLContext configuration, validators, and adjacent value types.

Covers parameter-validation guards, ``set_ciphers`` tiering,
``wrap_socket``/``wrap_bio`` direction checks, version-flag clamping,
and the small ``Certificate``/``SSLSession`` value-type API.

Live-handshake behaviour lives in :mod:`tests.test_handshake` and
:mod:`tests.test_compat`; this file is plumbing-only.
"""

from __future__ import annotations

import pickle
import socket as _socket
import warnings

import pytest

import utls
from utls import Certificate, Fingerprint, SSLContext, SSLError, SSLSession


# Parameter validators

def test_verify_mode_rejects_unknown_value():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(ValueError, match="invalid verify_mode"):
        ctx.verify_mode = 999


def test_set_ecdh_curve_rejects_non_string():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(TypeError, match="non-empty str"):
        ctx.set_ecdh_curve(123)  # type: ignore[arg-type]


def test_set_ecdh_curve_rejects_empty_string():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(TypeError, match="non-empty str"):
        ctx.set_ecdh_curve("")


def test_set_session_id_context_rejects_non_bytes():
    ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    with pytest.raises(TypeError, match="bytes-like"):
        ctx.set_session_id_context("not bytes")  # type: ignore[arg-type]


def test_num_tickets_rejects_negative():
    ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    with pytest.raises(ValueError, match="non-negative int"):
        ctx.num_tickets = -1


def test_num_tickets_rejects_non_int():
    ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    with pytest.raises(ValueError, match="non-negative int"):
        ctx.num_tickets = "five"  # type: ignore[assignment]


def test_set_fingerprint_rejects_wrong_type():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(TypeError, match="Fingerprint or preset name"):
        ctx.set_fingerprint(12345)  # type: ignore[arg-type]


# wrap_socket / wrap_bio direction checks

def test_wrap_socket_rejects_server_side_on_client_ctx():
    client_ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(ValueError, match="PROTOCOL_TLS_SERVER"):
        client_ctx.wrap_socket(_socket.socket(), server_side=True)


def test_wrap_socket_rejects_client_side_on_server_ctx():
    server_ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    with pytest.raises(ValueError, match="server_side=True"):
        server_ctx.wrap_socket(_socket.socket(), server_side=False)


def test_wrap_socket_rejects_server_hostname_on_server_side():
    server_ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    with pytest.raises(ValueError, match="server_hostname must be None"):
        server_ctx.wrap_socket(
            _socket.socket(), server_side=True, server_hostname="example.com"
        )


def test_wrap_bio_rejects_client_side_on_server_ctx():
    # Direct coverage of the wrap_bio direction-check branch; wrap_socket's
    # own up-front check would otherwise mask the wrap_bio path.
    server_ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    with pytest.raises(ValueError, match="pass server_side=True"):
        server_ctx.wrap_bio(inc, out, server_side=False)


# Version flag clamping

def test_op_no_tlsv1_2_raises_effective_minimum_to_1_3():
    from utls.constants import OP_NO_TLSv1_2

    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    # Default min is TLS1.2; flipping OP_NO_TLSv1_2 must clamp it up to 1.3.
    ctx.options |= OP_NO_TLSv1_2
    assert ctx.minimum_version == utls.TLSVersion.TLSv1_3


def test_tlsversion_accepts_stdlib_values():
    import ssl as _ssl

    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)

    # Every stdlib TLSVersion member must round-trip.
    ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    assert int(ctx.minimum_version) == int(_ssl.TLSVersion.TLSv1_2) == 771

    ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
    assert int(ctx.minimum_version) == int(_ssl.TLSVersion.TLSv1_3) == 772

    ctx.maximum_version = _ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert ctx.maximum_version == utls.TLSVersion.MAXIMUM_SUPPORTED

    ctx.minimum_version = _ssl.TLSVersion.MINIMUM_SUPPORTED
    assert ctx.minimum_version == utls.TLSVersion.MINIMUM_SUPPORTED

    # Lower-than-1.2 stdlib values: accepted (stdlib parity) even though
    # BoringSSL won't actually negotiate them; the handshake floor stays
    # at TLS 1.2. This is the exact value that triggered the original
    # ValueError in urllib3's create_urllib3_context.
    ctx.minimum_version = _ssl.TLSVersion.TLSv1  # 769
    assert int(ctx.minimum_version) == 769

    # Raw int assignment, in case a downstream caller bypasses the enum.
    ctx.minimum_version = 771
    assert ctx.minimum_version == utls.TLSVersion.TLSv1_2


def test_tlsversion_inverted_sentinels_collapse_to_library_default():
    import ssl as _ssl

    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)

    # min = MAXIMUM_SUPPORTED: must not raise, getter still returns it.
    ctx.minimum_version = _ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert ctx.minimum_version == utls.TLSVersion.MAXIMUM_SUPPORTED

    # Subsequent reassignments stay healthy (this is the exact sequence
    # that blew up in urllib3-future's nox env).
    ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = _ssl.TLSVersion.TLSv1_2

    # Symmetric case: max = MINIMUM_SUPPORTED should also collapse.
    ctx2 = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx2.maximum_version = _ssl.TLSVersion.MINIMUM_SUPPORTED
    assert ctx2.maximum_version == utls.TLSVersion.MINIMUM_SUPPORTED

    # Raw int form, as urllib3-future actually emits it.
    ctx3 = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx3.minimum_version = -1
    assert int(ctx3.minimum_version) == -1


def test_options_supports_membership_with_int_operands():
    import ssl as _ssl

    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    assert utls.OP_NO_TLSv1_3 not in ctx.options

    ctx.options |= utls.OP_NO_TLSv1_3
    assert isinstance(ctx.options, utls.Options)
    # Three operand shapes that all show up in real-world code.
    assert utls.OP_NO_TLSv1_3 in ctx.options
    assert _ssl.OP_NO_TLSv1_3 in ctx.options
    assert 0x20000000 in ctx.options


def test_protocol_constants_match_stdlib_and_accept_deprecated_aliases():
    import ssl as _ssl

    assert utls.PROTOCOL_TLS_CLIENT == int(_ssl.PROTOCOL_TLS_CLIENT) == 16
    assert utls.PROTOCOL_TLS_SERVER == int(_ssl.PROTOCOL_TLS_SERVER) == 17
    assert utls.PROTOCOL_TLS == 2
    assert utls.PROTOCOL_SSLv23 == utls.PROTOCOL_TLS
    assert utls.PROTOCOL_TLSv1 == 3
    assert utls.PROTOCOL_TLSv1_1 == 4
    assert utls.PROTOCOL_TLSv1_2 == 5

    # Constructor must accept the stdlib enum member directly.
    ctx = SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    assert ctx._server_side is False

    # Deprecated aliases all yield a client-side context (BoringSSL will
    # refuse to actually negotiate <1.2, but the API surface accepts them).
    for proto in (
        utls.PROTOCOL_TLS,
        utls.PROTOCOL_SSLv23,
        utls.PROTOCOL_TLSv1,
        utls.PROTOCOL_TLSv1_1,
        utls.PROTOCOL_TLSv1_2,
    ):
        ctx = SSLContext(proto)
        assert ctx._server_side is False


def test_hostname_checks_common_name_is_unsupported():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    assert hasattr(ctx, "hostname_checks_common_name") is False
    with pytest.raises(AttributeError, match="BoringSSL only checks SAN"):
        ctx.hostname_checks_common_name
    with pytest.raises(AttributeError, match="BoringSSL only checks SAN"):
        ctx.hostname_checks_common_name = True


# set_ciphers tiering (no fingerprint / fingerprint-bound / garbage)

def test_set_ciphers_passthrough_on_unbound_context():
    # Tier 1: no fingerprint installed -> forwarded to BoringSSL's
    # SSL_CTX_set_cipher_list. A lenient OpenSSL alias is accepted.
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("HIGH:!aNULL:!MD5")


def test_set_ciphers_warns_and_noops_when_fingerprint_active():
    # Tier 2: a fingerprint owns the ClientHello cipher list; honouring
    # set_ciphers would be a silent lie, so we warn and no-op.
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.set_fingerprint("chrome:131")
    fp_before = ctx.fingerprint.to_dict()["cipher_suites"]

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        ctx.set_ciphers("HIGH:!aNULL")

    assert any(
        issubclass(w.category, UserWarning) and "fingerprint is active" in str(w.message)
        for w in captured
    )
    # Fingerprint cipher list must be untouched.
    assert ctx.fingerprint.to_dict()["cipher_suites"] == fp_before


def test_set_ciphers_rejects_garbage_via_sslerror():
    # Tier 3: BoringSSL's parser is lenient on unknown tokens but rejects
    # truly malformed input. The empty-string case is the cleanest:
    # SSL_CTX_set_cipher_list returns 0 and _ErrorRemapping surfaces it.
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(SSLError):
        ctx.set_ciphers("")


# session_stats stub

def test_session_stats_returns_empty_mapping():
    # BoringSSL does not track stdlib-style resumption counters; we
    # return {} for parity with ssl.SSLContext.session_stats().
    ctx = SSLContext(utls.PROTOCOL_TLS_SERVER)
    assert ctx.session_stats() == {}


# Certificate value type

def test_certificate_repr_reports_der_length():
    der = bytes(range(48))
    cert = Certificate(der, utls.create_default_context())
    assert repr(cert) == f"<utls.Certificate ({len(der)} bytes DER)>"


# SSLSession value type

def test_sslsession_from_der_rejects_empty_blob():
    with pytest.raises(ValueError, match="empty"):
        SSLSession.from_der(b"")


def test_sslsession_pickle_reducer_advertises_from_der():
    # __reduce__ contract: (callable, args-tuple). We verify the shape
    # without owning a real session by stubbing the inner _session.
    class FakeInner:
        def to_der(self) -> bytes:
            return b"some-session-der"

    s = SSLSession(FakeInner())
    callable_, args = s.__reduce__()
    # classmethod returns a fresh bound-method object on each access, so
    # compare the underlying function, not the bound objects.
    assert callable_.__func__ is SSLSession.from_der.__func__
    assert args == (b"some-session-der",)
    # The wider pickle pipeline at least gets to __reduce__: dumps()
    # must succeed even though loads() would fail (from_der rejects the
    # fake blob).
    pickle.dumps(s)


# Ensure unused import remains referenced for typing; silences linters.
_ = Fingerprint

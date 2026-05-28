from __future__ import annotations

import pytest

import utls


def _read(ctx: utls.SSLContext) -> bytes | None:
    """Test-only ECH readback via the internal core binding."""
    return ctx._ctx.ech_config_list()


# A syntactically-shaped but semantically-invalid ECHConfigList. BoringSSL's
# `SSL_set1_ech_config_list` performs structural validation at install time -
# enough to ensure a junk blob is rejected - which is exactly what we want to
# observe as a wire-up smoke test without needing a live ECH publisher.
SAMPLE_ECH_CONFIG_LIST = bytes.fromhex(
    "0041"
    "fe0d"
    "003d"
    "00"
    "0020"
    "0020"
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "0004" "0001" "0001"
    "00"
    "07" "6563682e646576"
    "0000"
)


def test_set_ech_configs_returns_new_context():
    """`set_ech_configs` must return a distinct `SSLContext` instance."""
    base = utls.SSLContext()
    forked = base.set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    assert forked is not base
    assert isinstance(forked, utls.SSLContext)


def test_set_ech_configs_does_not_mutate_base():
    """The base context must remain ECH-less after forking."""
    base = utls.SSLContext()
    assert _read(base) is None
    _ = base.set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    assert _read(base) is None, (
        "set_ech_configs mutated the base context - it must be non-mutating"
    )


def test_forked_context_carries_ech_config_list():
    base = utls.SSLContext()
    forked = base.set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    assert _read(forked) == SAMPLE_ECH_CONFIG_LIST


def test_set_ech_configs_none_clears_on_fork():
    """Forking with `None` produces a clone with no ECH override, even if
    we'd already forked with bytes (i.e. forking is composable)."""
    base = utls.SSLContext()
    a = base.set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    b = a.set_ech_configs(None)
    assert _read(a) == SAMPLE_ECH_CONFIG_LIST
    assert _read(b) is None


def test_set_ech_configs_accepts_bytes_like():
    base = utls.SSLContext()
    for variant in (
        bytes(SAMPLE_ECH_CONFIG_LIST),
        bytearray(SAMPLE_ECH_CONFIG_LIST),
        memoryview(SAMPLE_ECH_CONFIG_LIST),
    ):
        forked = base.set_ech_configs(variant)
        assert _read(forked) == SAMPLE_ECH_CONFIG_LIST


def test_set_ech_configs_rejects_non_bytes():
    base = utls.SSLContext()
    with pytest.raises(TypeError, match="bytes-like"):
        base.set_ech_configs("not bytes")  # type: ignore[arg-type]


def test_forked_context_inherits_fingerprint():
    """Snapshot semantics: the fork captures the base's fingerprint at
    clone-time. Subsequent mutations on the base must not affect the fork."""
    base = utls.SSLContext()
    base.set_fingerprint("chrome:131")
    forked = base.set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    assert forked.fingerprint is not None
    assert forked.fingerprint.ja4_hash == base.fingerprint.ja4_hash

    # Mutate base; fork must keep its snapshot.
    base.set_fingerprint("chrome:142")
    assert base.fingerprint.ja4_hash != forked.fingerprint.ja4_hash


def test_invalid_ech_config_list_rejected_at_wrap_bio():
    """BoringSSL's `SSL_set1_ech_config_list` validates structure at install
    time; our junk fixture must be rejected as `INVALID_ECH_CONFIG_LIST`.
    This proves the override is wired all the way through to BoringSSL.

    The positive path - a server-accepted ECH handshake - requires a real
    ECHConfigList published in DNS HTTPS RR and a cooperating origin.
    """
    ctx = utls.SSLContext().set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    with pytest.raises(utls.SSLError, match="INVALID_ECH_CONFIG_LIST"):
        ctx.wrap_bio(inc, out, server_hostname="example.com")


def test_ech_accessors_pre_handshake():
    """`SSLObject.ech_accepted()` and `ech_retry_configs()` live on the live
    state machine (like `cipher()` and `version()`) and must return the
    "no answer yet" sentinels (False / None) before the handshake completes,
    on a context with no ECH override at all."""
    ctx = utls.SSLContext()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    conn = ctx.wrap_bio(inc, out, server_hostname="example.com")
    assert conn.ech_accepted() is False
    assert conn.ech_retry_configs() is None


def test_base_context_shared_ssl_ctx_does_not_leak_on_drop():
    """A forked context up-refs the underlying SSL_CTX. Dropping the base
    while a fork is still alive (and vice versa) must not segfault - this
    is a smoke test for the refcount handling around `SSL_CTX_up_ref`.
    """
    base = utls.SSLContext()
    base.load_default_certs()
    forked = base.set_ech_configs(SAMPLE_ECH_CONFIG_LIST)
    del base
    # `forked` must remain fully usable (wrap_bio is rejected for invalid
    # ECH but should not segfault - pytest catches abort signals).
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    with pytest.raises(utls.SSLError):
        forked.wrap_bio(inc, out, server_hostname="example.com")

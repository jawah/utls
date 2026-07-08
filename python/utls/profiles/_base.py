from __future__ import annotations

import enum


class Ext(enum.IntEnum):
    """IANA TLS extension codepoints we reference from profiles."""

    server_name = 0
    status_request = 5
    supported_groups = 10
    ec_point_formats = 11
    signature_algorithms = 13
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    padding = 21
    extended_master_secret = 23
    record_size_limit = 28
    session_ticket = 35
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    psk_key_exchange_modes = 45
    key_share = 51
    compress_certificate = 27
    renegotiation_info = 65281
    # Original ALPS (Application-Layer Protocol Settings) codepoint, used by
    # Chrome 109-123. Chrome 124+ moved to ``application_settings_new``
    # (0x44CD); see the chromium-side rename in BoringSSL upstream.
    application_settings = 17513  # 0x4469
    application_settings_new = 17613  # 0x44CD
    encrypted_client_hello = 65037
    # utls-private sentinel: see module docstring.
    GREASE = 0xFFFE


class Group(enum.IntEnum):
    """IANA Supported Groups codepoints (TLS 1.3 NamedGroup)."""

    # Classical ECDHE
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E
    # FFDHE (rarely used by browsers)
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    # Hybrid post-quantum (Chrome 124+).
    X25519MLKEM768 = 0x11EC
    # Older Kyber hybrid; kept for completeness.
    X25519Kyber768Draft00 = 0x6399


class SigAlg(enum.IntEnum):
    """IANA signature scheme codepoints for the `signature_algorithms` extension."""

    # ECDSA
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    # RSA PSS (RSAE)
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    # RSA PKCS#1 v1.5 (legacy, still sent for TLS 1.2 interop)
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601
    rsa_pkcs1_sha1 = 0x0201
    # Ed25519 / Ed448
    ed25519 = 0x0807
    ed448 = 0x0808
    # Post-quantum ML-DSA. Chrome 150+ advertises these.
    mldsa44 = 0x0904
    mldsa65 = 0x0905
    mldsa87 = 0x0906

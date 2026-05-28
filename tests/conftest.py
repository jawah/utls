from __future__ import annotations

import os
import socket

import pytest


@pytest.fixture(scope="session")
def _network_available() -> bool:
    """Probe outbound TCP/443 reachability once per session.
    Honors the ``UTLS_NO_NETWORK=1`` env var.
    """
    if os.environ.get("UTLS_NO_NETWORK") == "1":
        return False
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 443)):
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            continue
    return False


@pytest.fixture
def requires_network(_network_available: bool) -> None:
    """Skip the requesting test if outbound network is not reachable."""
    if not _network_available:
        pytest.skip("network unavailable (no outbound TCP/443 reachable)")


@pytest.fixture(scope="session")
def _trustme():
    """Lazy-import trustme so the whole suite doesn't hard-fail if it's
    missing - only tests that depend on it should skip."""
    pytest.importorskip("trustme")
    import trustme
    return trustme


@pytest.fixture(scope="session")
def ca(_trustme):
    return _trustme.CA()


@pytest.fixture(scope="session")
def server_cert(ca):
    return ca.issue_cert("localhost", "127.0.0.1")


@pytest.fixture(scope="session")
def ca_pem_path(tmp_path_factory, ca):
    p = tmp_path_factory.mktemp("ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(p))
    return str(p)


@pytest.fixture(scope="session")
def server_cert_files(tmp_path_factory, server_cert):
    """Persist server cert+key to disk; return (certfile, keyfile)."""
    d = tmp_path_factory.mktemp("server")
    c = d / "cert.pem"
    k = d / "key.pem"
    server_cert.cert_chain_pems[0].write_to_path(str(c))
    server_cert.private_key_pem.write_to_path(str(k))
    return str(c), str(k)


def make_utls_server(server_cert_files):
    """Build an utls server context loaded with the shared leaf cert+key."""
    import utls
    cert, key = server_cert_files
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def make_stdlib_server(server_cert_files):
    """Build a stdlib ssl server context (used by interop tests)."""
    import ssl
    cert, key = server_cert_files
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def make_utls_client(ca_pem_path):
    """Trusts the shared test CA."""
    import utls
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_pem_path)
    return ctx


def make_stdlib_client(ca_pem_path):
    import ssl
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(ca_pem_path)
    return ctx

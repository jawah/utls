from __future__ import annotations

import ssl as _stdlib_ssl


class SSLError(_stdlib_ssl.SSLError):
    """Generic TLS error. Base class for everything in this module."""


class SSLWantReadError(SSLError, _stdlib_ssl.SSLWantReadError):
    """A non-blocking TLS op needs to read more from the peer before progressing."""


class SSLWantWriteError(SSLError, _stdlib_ssl.SSLWantWriteError):
    """A non-blocking TLS op needs the caller to flush outgoing data."""


class SSLEOFError(SSLError, _stdlib_ssl.SSLEOFError):
    """The peer closed the connection without sending close_notify."""


class SSLZeroReturnError(SSLError, _stdlib_ssl.SSLZeroReturnError):
    """The peer sent close_notify; the connection is cleanly shut."""


class SSLSyscallError(SSLError, _stdlib_ssl.SSLSyscallError):
    """A non-recoverable syscall (read/write) failed underneath the TLS
    state machine."""


class SSLCertVerificationError(SSLError, _stdlib_ssl.SSLCertVerificationError):
    """Certificate chain or hostname verification failed."""

    verify_code: int | None = None
    verify_message: str | None = None

    def __init__(self, message: str, *, verify_code: int | None = None) -> None:
        super().__init__(message)
        self.verify_code = verify_code
        self.verify_message = message


# Stdlib alias.
CertificateError = SSLCertVerificationError

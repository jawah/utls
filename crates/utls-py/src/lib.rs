//! PyO3 bindings -> the `_utls` Python extension module.
//!
//! The Python-facing API lives in the `utls` pure-Python package (under
//! `python/utls/`). This crate is intentionally thin: it exposes raw,
//! opinionated handles (`Context`, `Connection`, `MemoryBio`, `Session`,
//! `Fingerprint`) and delegates *all* policy (defaults, exception mapping
//! into the public hierarchy, OP_* flag handling) to the Python facade.
//!
//! ## Threading & GIL
//!
//! Every operation that could block on TLS state-machine work (handshake,
//! read, write, shutdown) releases the GIL via `py.detach(...)`. The Rust
//! side calls back into Python in exactly one place - the server-side SNI
//! dispatcher (`set_servername_callback`) - and it re-acquires the GIL via
//! `Python::attach` from inside the BoringSSL callback.
//!
//! ## Object model
//!
//! * `_utls.Context`     - wraps `utls_core::Context`. Reusable, thread-safe.
//! * `_utls.Connection`  - one TLS conversation; owns memory BIOs and the
//!   `SSL*`. Not thread-safe (Python-level lock if needed).
//! * `_utls.MemoryBio`   - the Python-owned I/O ring; per direction.
//! * `_utls.Session`     - opaque, picklable (DER under the hood).
//! * `_utls.Fingerprint` - declarative spec; immutable from Python.
//!
//! Errors are exposed as a single top-level `_utls.CoreError` exception that
//! carries a `.kind` string. The Python facade pattern-matches on `.kind`
//! and re-raises into the user-facing `SSLError` hierarchy. This keeps the
//! Rust->Python error path simple and avoids registering a giant exception
//! class tree in Rust.

// pyo3 0.22's #[pymethods] macro generates calls to unsafe functions
// without explicit `unsafe {}` blocks; on Rust 2024 / with this lint
// promoted to `deny` the macro expansion fails. Keep as `warn` here
// (the underlying functions remain unsafe at the C-FFI boundary in
// `utls-core`, which still has `deny(unsafe_op_in_unsafe_fn)`).
#![warn(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use pyo3::IntoPyObjectExt;

use utls_core as core;

create_exception!(_utls, CoreError, pyo3::exceptions::PyException);

fn map_err(err: core::Error) -> PyErr {
    use core::Error::*;
    let (kind, message, extra): (&str, String, Option<Py<PyAny>>) = match &err {
        WantRead => ("WantRead", err.to_string(), None),
        WantWrite => ("WantWrite", err.to_string(), None),
        Eof => ("Eof", err.to_string(), None),
        ZeroReturn => ("ZeroReturn", err.to_string(), None),
        Verification {
            reason,
            verify_code,
        } => (
            "Verification",
            reason.clone(),
            // Stuff verify_code into the args list for the Python facade.
            // `into_py_any` is fallible in pyo3 0.28; in practice it cannot
            // fail for an `i64`, so unwrap_or(None) is fine here.
            Python::attach(|py| verify_code.unwrap_or(0).into_py_any(py).ok()),
        ),
        Protocol { message, .. } => ("Protocol", message.clone(), None),
        Usage(_) => return PyValueError::new_err(err.to_string()),
        Io(_) => ("Io", err.to_string(), None),
        Unsupported(_) => return pyo3::exceptions::PyNotImplementedError::new_err(err.to_string()),
    };
    Python::attach(|py| {
        let exc = CoreError::new_err((kind.to_string(), message));
        if let Some(extra) = extra {
            // Attach as a custom attr so the Python facade can pull it out.
            if let Ok(val) = exc.value(py).getattr("args") {
                let _ = val; // we keep the standard args; verify_code goes to .verify_code
            }
            let _ = exc.value(py).setattr("verify_code", extra);
        }
        exc
    })
}

// `frozen` (not `unsendable`) so callers in different OS threads - asyncio
// loops, thread-pool executors, urllib3 connection pools - can touch the
// same handle without PyO3 panicking. All mutable state is behind a Mutex
// that we acquire *inside* `py.detach(...)` for blocking ops so the GIL is
// released for the duration of the crypto work. With `&self` everywhere,
// PyO3's PyCell borrow checker is also bypassed entirely -> no
// "RuntimeError: Already borrowed" surprises.
#[pyclass(name = "MemoryBio", module = "_utls", frozen)]
struct PyMemoryBio {
    inner: Mutex<core::MemoryBio>,
}

#[pymethods]
impl PyMemoryBio {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(core::MemoryBio::new().map_err(map_err)?),
        })
    }

    #[getter]
    fn pending(&self) -> usize {
        self.inner.lock().unwrap().pending()
    }

    #[getter]
    fn eof(&self) -> bool {
        self.inner.lock().unwrap().eof()
    }

    /// Drain up to `n` bytes. `n=-1` means "all currently pending".
    ///
    /// Released GIL during the actual BIO drain so concurrent Python threads
    /// (a parallel asyncio task, a background `requests` worker, ...) make
    /// progress during multi-MB streaming reads. The final `PyBytes` copy
    /// happens after re-attach: it touches the Python heap and must hold
    /// the GIL anyway.
    #[pyo3(signature = (n = -1))]
    fn read<'py>(&self, py: Python<'py>, n: isize) -> PyResult<Bound<'py, PyBytes>> {
        let max = if n < 0 { None } else { Some(n as usize) };
        let bytes = py
            .detach(|| self.inner.lock().unwrap().read(max))
            .map_err(map_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Push wire bytes into the BIO. Detaches the GIL for the memcpy +
    /// internal-buffer growth path so high-throughput recv loops don't pin
    /// the interpreter. `data` is borrowed from a Python `bytes` (immutable)
    /// in every real-world call site - the borrow remains valid across the
    /// detach because `bytes` is immutable and refcounted by the caller.
    fn write(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        py.detach(|| self.inner.lock().unwrap().write(data))
            .map_err(map_err)
    }

    fn write_eof(&self) {
        self.inner.lock().unwrap().write_eof();
    }
}

#[pyclass(name = "Session", module = "_utls", frozen)]
struct PySession {
    inner: Mutex<core::Session>,
}

#[pymethods]
impl PySession {
    fn to_der<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let der = self.inner.lock().unwrap().to_der().map_err(map_err)?;
        Ok(PyBytes::new(py, &der))
    }

    #[staticmethod]
    fn from_der(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(core::Session::from_der(data).map_err(map_err)?),
        })
    }

    // Pickle hooks: __reduce__ returns (from_der, (bytes,)) - simple and
    // guaranteed to round-trip via DER.
    fn __reduce__<'py>(&self, py: Python<'py>) -> PyResult<(Py<PyAny>, Py<PyAny>)> {
        let der = self.inner.lock().unwrap().to_der().map_err(map_err)?;
        let module = py.import("_utls")?;
        let cls = module.getattr("Session")?;
        let ctor = cls.getattr("from_der")?;
        let args = (PyBytes::new(py, &der),);
        Ok((ctor.unbind(), args.into_py_any(py)?))
    }
}

#[pyclass(name = "Fingerprint", module = "_utls", frozen)]
struct PyFingerprint {
    inner: core::Fingerprint,
}

#[pymethods]
impl PyFingerprint {
    #[new]
    #[pyo3(signature = (
        cipher_suites = None,
        extensions_order = None,
        supported_groups = None,
        key_shares = None,
        signature_algorithms = None,
        alpn = None,
        alps = None,
        alps_use_new_codepoint = true,
        compress_certificate = None,
        record_size_limit = None,
        grease = true,
        grease_sigalgs = false,
        ech = None,
        padding = None,
        trust_anchors = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        cipher_suites: Option<Vec<u16>>,
        extensions_order: Option<Vec<u16>>,
        supported_groups: Option<Vec<u16>>,
        key_shares: Option<Vec<u16>>,
        signature_algorithms: Option<Vec<u16>>,
        alpn: Option<Vec<String>>,
        alps: Option<Vec<String>>,
        alps_use_new_codepoint: bool,
        compress_certificate: Option<Vec<String>>,
        record_size_limit: Option<u16>,
        grease: bool,
        grease_sigalgs: bool,
        ech: Option<Py<PyAny>>,
        padding: Option<usize>,
        trust_anchors: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let mut b = core::Fingerprint::builder()
            .cipher_suites(cipher_suites.unwrap_or_default())
            .extensions_order(extensions_order.unwrap_or_default())
            .supported_groups(supported_groups.unwrap_or_default())
            .key_shares(key_shares.unwrap_or_default())
            .signature_algorithms(signature_algorithms.unwrap_or_default())
            .alpn(alpn.unwrap_or_default())
            .alps(alps.unwrap_or_default())
            .alps_use_new_codepoint(alps_use_new_codepoint)
            .record_size_limit(record_size_limit)
            .grease(grease)
            .grease_sigalgs(grease_sigalgs)
            .padding(padding)
            .trust_anchors(trust_anchors);
        if let Some(names) = compress_certificate {
            let mut algs = Vec::with_capacity(names.len());
            for n in names {
                let alg = core::fingerprint::spec::CertCompressAlg::from_name(&n)
                    .ok_or_else(|| PyValueError::new_err(format!(
                        "unknown compress_certificate algorithm: {n:?} (allowed: zlib, brotli, zstd)"
                    )))?;
                algs.push(alg);
            }
            b = b.compress_certificate(algs);
        }
        let ech_policy = match ech {
            None => core::fingerprint::spec::EchPolicy::Off,
            Some(obj) => Python::attach(|py| -> PyResult<_> {
                let any = obj.bind(py);
                if let Ok(flag) = any.extract::<bool>() {
                    Ok(if flag {
                        core::fingerprint::spec::EchPolicy::Grease
                    } else {
                        core::fingerprint::spec::EchPolicy::Off
                    })
                } else if let Ok(bytes) = any.extract::<&[u8]>() {
                    Ok(core::fingerprint::spec::EchPolicy::Real(bytes.to_vec()))
                } else {
                    Err(PyValueError::new_err("ech must be bool or bytes"))
                }
            })?,
        };
        Ok(Self {
            inner: b.ech(ech_policy).build(),
        })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in self.inner.to_btreemap() {
            use core::fingerprint::spec::FpValue::*;
            let value: Py<PyAny> = match v {
                U16Vec(xs) => xs.into_py_any(py)?,
                StringVec(xs) => xs.into_py_any(py)?,
                OptU16(x) => x.into_py_any(py)?,
                OptUsize(x) => x.into_py_any(py)?,
                Bool(x) => x.into_py_any(py)?,
                Str(x) => x.into_py_any(py)?,
                Bytes(x) => PyBytes::new(py, &x).into_py_any(py)?,
                OptBytes(None) => py.None().into_py_any(py)?,
                OptBytes(Some(x)) => PyBytes::new(py, &x).into_py_any(py)?,
            };
            d.set_item(k, value)?;
        }
        Ok(d)
    }

    fn ja3_string(&self) -> String {
        core::fingerprint::ja3::ja3_string(&self.inner)
    }
    fn ja3_hash(&self) -> String {
        core::fingerprint::ja3::ja3_hash(&self.inner)
    }
    fn ja4_string(&self) -> String {
        core::fingerprint::ja4::ja4_string(&self.inner)
    }
    fn ja4_hash(&self) -> String {
        core::fingerprint::ja4::ja4_hash(&self.inner)
    }

    /// Parse a raw ClientHello record and return a fresh Fingerprint.
    #[staticmethod]
    fn from_capture(raw: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: core::fingerprint::capture::parse_client_hello(raw).map_err(map_err)?,
        })
    }
}

#[pyclass(name = "Context", module = "_utls", frozen)]
struct PyContext {
    inner: core::Context,
}

#[pymethods]
impl PyContext {
    /// `protocol` is the integer encoding of `ssl.PROTOCOL_TLS_CLIENT` (2)
    /// or `ssl.PROTOCOL_TLS_SERVER` (3); the Python facade enforces the
    /// symbolic constant.
    #[new]
    #[pyo3(signature = (protocol = 2))]
    fn new(protocol: i32) -> PyResult<Self> {
        let proto = match protocol {
            2 => core::context::Protocol::TlsClient,
            3 => core::context::Protocol::TlsServer,
            _ => {
                return Err(PyValueError::new_err(
                    "protocol must be PROTOCOL_TLS_CLIENT (2) or PROTOCOL_TLS_SERVER (3)",
                ));
            }
        };
        Ok(Self {
            inner: core::Context::new(proto).map_err(map_err)?,
        })
    }

    /// Whether this context handshakes as a TLS server.
    fn is_server(&self) -> bool {
        self.inner.is_server()
    }

    // verify mode / hostname
    fn set_verify_mode(&self, mode: u8) -> PyResult<()> {
        let m = match mode {
            0 => core::VerifyMode::None,
            1 => core::VerifyMode::Optional,
            2 => core::VerifyMode::Required,
            _ => return Err(PyValueError::new_err("verify_mode must be 0, 1, or 2")),
        };
        self.inner.set_verify_mode(m).map_err(map_err)
    }
    fn verify_mode(&self) -> u8 {
        match self.inner.verify_mode() {
            core::VerifyMode::None => 0,
            core::VerifyMode::Optional => 1,
            core::VerifyMode::Required => 2,
        }
    }

    fn set_check_hostname(&self, v: bool) -> PyResult<()> {
        self.inner.set_check_hostname(v).map_err(map_err)
    }
    fn check_hostname(&self) -> bool {
        self.inner.check_hostname()
    }

    fn set_version_bounds(&self, min: u8, max: u8) -> PyResult<()> {
        let to = |v: u8| -> PyResult<core::TlsVersion> {
            Ok(match v {
                0 => core::TlsVersion::MinimumSupported,
                2 => core::TlsVersion::Tls1_2,
                3 => core::TlsVersion::Tls1_3,
                9 => core::TlsVersion::MaximumSupported,
                _ => return Err(PyValueError::new_err("invalid TLS version code")),
            })
        };
        self.inner
            .set_version_bounds(to(min)?, to(max)?)
            .map_err(map_err)
    }

    // alpn / ciphers
    fn set_alpn_protocols(&self, protocols: Vec<String>) -> PyResult<()> {
        let refs: Vec<&str> = protocols.iter().map(String::as_str).collect();
        self.inner.set_alpn_protocols(&refs).map_err(map_err)
    }
    fn set_ciphers(&self, spec: &str) -> PyResult<()> {
        self.inner.set_ciphers(spec).map_err(map_err)
    }

    // trust
    #[pyo3(signature = (cafile = None, capath = None))]
    fn load_verify_locations(
        &self,
        py: Python<'_>,
        cafile: Option<&str>,
        capath: Option<&str>,
    ) -> PyResult<()> {
        py.detach(|| self.inner.load_verify_locations(cafile, capath))
            .map_err(map_err)
    }
    fn add_trusted_cert_der(&self, der: &[u8]) -> PyResult<()> {
        self.inner.add_trusted_cert_der(der).map_err(map_err)
    }
    #[pyo3(signature = (purpose = 0))]
    fn load_default_certs(&self, py: Python<'_>, purpose: u8) -> PyResult<()> {
        let p = match purpose {
            0 => core::Purpose::ServerAuth,
            1 => core::Purpose::ClientAuth,
            _ => {
                return Err(PyValueError::new_err(
                    "purpose must be 0 (SERVER_AUTH) or 1 (CLIENT_AUTH)",
                ))
            }
        };
        py.detach(|| self.inner.load_default_certs(p))
            .map_err(map_err)
    }
    #[pyo3(signature = (cert_pem, key_pem = None, password = None))]
    fn load_cert_chain(
        &self,
        py: Python<'_>,
        cert_pem: &[u8],
        key_pem: Option<&[u8]>,
        password: Option<&[u8]>,
    ) -> PyResult<()> {
        py.detach(|| self.inner.load_cert_chain(cert_pem, key_pem, password))
            .map_err(map_err)
    }

    /// Return ``(x509_count, crl_count)`` for the trust store. Callers in
    /// Python build the ``ssl.SSLContext.cert_store_stats()`` dict from this.
    fn cert_store_counts(&self) -> (usize, usize) {
        self.inner.cert_store_counts()
    }

    /// Return every CA cert in the trust store as a list of DER bytes.
    /// Mirrors ``ssl.SSLContext.get_ca_certs(binary_form=True)``.
    fn ca_certs_der<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let v = self.inner.ca_certs_der().map_err(map_err)?;
        Ok(v.into_iter().map(|b| PyBytes::new(py, &b)).collect())
    }

    /// Decode a raw DER X.509 cert into the stdlib-shaped getpeercert dict.
    /// Backs ``SSLContext.get_ca_certs(binary_form=False)`` and the
    /// ``Certificate.get_info()`` shim consumed by urllib3.future's chain
    /// walker. Returns ``None`` for empty/malformed input.
    fn decode_cert_der<'py>(
        &self,
        py: Python<'py>,
        der: &[u8],
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let info = core::peer_cert::decode_cert_der(der).map_err(map_err)?;
        match info {
            None => Ok(None),
            Some(info) => Ok(Some(peer_cert_info_to_pydict(py, &info)?)),
        }
    }

    // fingerprint
    fn set_fingerprint(&self, fp: Option<&PyFingerprint>) -> PyResult<()> {
        self.inner
            .set_fingerprint(fp.map(|f| f.inner.clone()))
            .map_err(map_err)
    }

    fn fingerprint(&self) -> Option<PyFingerprint> {
        self.inner
            .fingerprint()
            .map(|inner| PyFingerprint { inner })
    }

    fn set_session_id_context(&self, ctx_id: &[u8]) -> PyResult<()> {
        self.inner.set_session_id_context(ctx_id).map_err(map_err)
    }

    /// `set_ecdh_curve` accepts either a single curve name or an
    /// OpenSSL-style colon-separated list.
    fn set_curves_list(&self, names: &str) -> PyResult<()> {
        self.inner.set_curves_list(names).map_err(map_err)
    }

    fn set_num_tickets(&self, n: usize) -> PyResult<()> {
        self.inner.set_num_tickets(n).map_err(map_err)
    }

    fn num_tickets(&self) -> usize {
        self.inner.num_tickets()
    }

    fn verify_flags(&self) -> u64 {
        self.inner.verify_flags()
    }

    fn set_verify_flags(&self, flags: u64) -> PyResult<()> {
        self.inner.set_verify_flags(flags).map_err(map_err)
    }

    /// `path = None` clears the keylog callback.
    fn set_keylog_filename(&self, path: Option<&str>) -> PyResult<()> {
        self.inner.set_keylog_filename(path).map_err(map_err)
    }

    /// Install (or clear, with `None`) a server-side SNI dispatcher. The
    /// callable receives `(SniHandshakeView, server_name)` where `server_name`
    /// is the SNI string the client sent or `None`. Return `None` to accept
    /// the handshake (optionally after calling `view.swap_context(other_ctx)`)
    /// or an `int` in `0..=255` to abort with that TLS alert.
    ///
    /// Server-side only. Raises on a client context.
    fn set_sni_callback(&self, py: Python<'_>, callback: Option<Py<PyAny>>) -> PyResult<()> {
        match callback {
            None => self.inner.set_sni_dispatcher(None).map_err(map_err),
            Some(cb) => {
                if !cb.bind(py).is_callable() {
                    return Err(PyTypeError::new_err(
                        "SNI callback must be callable or None",
                    ));
                }
                let dispatcher: Arc<dyn core::SniDispatcher> = Arc::new(PySniDispatcher { cb });
                self.inner
                    .set_sni_dispatcher(Some(dispatcher))
                    .map_err(map_err)
            }
        }
    }

    // ECH override. Non-mutating: returns a *new* Context that shares the
    // underlying SSL_CTX (and so the trust store) with `self` but carries the
    // supplied ECHConfigList bytes. Pass `None` to clear in the clone.
    // Method name matches rtls.SSLContext.set_ech_configs so urllib3.future's
    // `hasattr(ctx, "set_ech_configs")` probe succeeds.
    fn set_ech_configs(&self, ech: Option<&[u8]>) -> PyContext {
        PyContext {
            inner: self.inner.set_ech_configs(ech.map(|b| b.to_vec())),
        }
    }

    /// Read back the currently-installed ECH ConfigList bytes.
    /// Test-only diagnostic; intentionally not surfaced on the Python
    /// `SSLContext` facade because urllib3.future never reads ECH config back.
    fn ech_config_list<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.ech_config_list().map(|b| PyBytes::new(py, &b))
    }

    // wrap
    #[pyo3(signature = (incoming, outgoing, server_hostname = None, session = None))]
    fn wrap_bio(
        &self,
        incoming: &PyMemoryBio,
        outgoing: &PyMemoryBio,
        server_hostname: Option<&str>,
        session: Option<&PySession>,
    ) -> PyResult<PyConnection> {
        let inc = incoming.inner.lock().unwrap();
        let out = outgoing.inner.lock().unwrap();
        let sess_lock = session.map(|s| s.inner.lock().unwrap());
        let conn = self
            .inner
            .wrap_bio(&inc, &out, server_hostname, sess_lock.as_deref())
            .map_err(map_err)?;
        Ok(PyConnection {
            inner: Mutex::new(conn),
        })
    }
}

#[pyclass(name = "Connection", module = "_utls", frozen)]
struct PyConnection {
    inner: Mutex<core::context::Connection>,
}

#[pymethods]
impl PyConnection {
    fn do_handshake(&self, py: Python<'_>) -> PyResult<bool> {
        // SAFETY: allow_threads is safe - we release the GIL around blocking
        // crypto work and we never call back into Python from Rust threads.
        py.detach(|| self.inner.lock().unwrap().do_handshake())
            .map_err(map_err)
    }

    fn read<'py>(&self, py: Python<'py>, n: usize) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = py
            .detach(|| self.inner.lock().unwrap().read(n))
            .map_err(map_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    fn write(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        py.detach(|| self.inner.lock().unwrap().write(data))
            .map_err(map_err)
    }

    fn shutdown(&self, py: Python<'_>) -> PyResult<bool> {
        py.detach(|| self.inner.lock().unwrap().shutdown())
            .map_err(map_err)
    }

    fn selected_alpn(&self) -> Option<String> {
        self.inner.lock().unwrap().selected_alpn()
    }
    fn version(&self) -> Option<&'static str> {
        self.inner.lock().unwrap().version()
    }
    fn cipher(&self) -> Option<(String, &'static str, i32)> {
        self.inner.lock().unwrap().cipher()
    }
    fn session(&self) -> Option<PySession> {
        self.inner.lock().unwrap().session().map(|s| PySession {
            inner: Mutex::new(s),
        })
    }
    fn session_reused(&self) -> bool {
        self.inner.lock().unwrap().session_reused()
    }

    fn ech_accepted(&self) -> bool {
        self.inner.lock().unwrap().ech_accepted()
    }

    fn ech_retry_configs<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .lock()
            .unwrap()
            .ech_retry_configs()
            .map(|b| PyBytes::new(py, &b))
    }

    fn is_server(&self) -> bool {
        self.inner.lock().unwrap().is_server()
    }

    /// Server-side: SNI value sent by the peer in its ClientHello.
    fn peer_sni(&self) -> Option<String> {
        self.inner.lock().unwrap().peer_sni()
    }

    /// Server-side: parsed [`Fingerprint`] for the captured peer ClientHello,
    /// or `None` if no CH was captured / this is a client connection.
    fn observed_client_fingerprint(&self) -> Option<PyFingerprint> {
        self.inner
            .lock()
            .unwrap()
            .observed_client_fingerprint()
            .map(|inner| PyFingerprint { inner })
    }

    fn peer_chain_der<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let chain = self
            .inner
            .lock()
            .unwrap()
            .peer_chain_der()
            .map_err(map_err)?;
        let list = PyList::empty(py);
        for der in chain {
            list.append(PyBytes::new(py, &der))?;
        }
        Ok(list)
    }

    /// Backs `SSLObject.getpeercert(binary_form=False)`. Returns `None` if no
    /// peer cert is available; otherwise a dict whose shape matches CPython's
    /// `ssl.SSLSocket.getpeercert()` exactly so ecosystem callers (urllib3
    /// hostname recheck, monitoring tools, custom verifiers) see a familiar
    /// surface.
    fn peer_cert_info<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        let info = self
            .inner
            .lock()
            .unwrap()
            .peer_cert_info()
            .map_err(map_err)?;
        match info {
            None => Ok(None),
            Some(info) => Ok(Some(peer_cert_info_to_pydict(py, &info)?)),
        }
    }
}

/// Standalone helper that materialises a `PeerCertInfo` into the stdlib-shaped
/// `PyDict`. Shared between `Connection.peer_cert_info` (live peer cert) and
/// `Context.decode_cert_der` (CA-store cert / chain element).
fn peer_cert_info_to_pydict<'py>(
    py: Python<'py>,
    info: &core::peer_cert::PeerCertInfo,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);

    // subject / issuer: tuple-of-RDNs-of-(name, value) - each RDN is
    // itself a tuple (CPython allows multi-attribute RDNs in there). We
    // emit one (name, value) per RDN; see `peer_cert.rs`.
    let to_name = |groups: &Vec<Vec<(String, String)>>| -> PyResult<Py<PyTuple>> {
        let rdns: Vec<Py<PyTuple>> = groups
            .iter()
            .map(|rdn| {
                let pairs: Vec<Py<PyTuple>> = rdn
                    .iter()
                    .map(|(k, v)| PyTuple::new(py, [k.as_str(), v.as_str()]).map(|t| t.unbind()))
                    .collect::<PyResult<Vec<_>>>()?;
                PyTuple::new(py, pairs).map(|t| t.unbind())
            })
            .collect::<PyResult<Vec<_>>>()?;
        PyTuple::new(py, rdns).map(|t| t.unbind())
    };
    d.set_item("subject", to_name(&info.subject)?)?;
    d.set_item("issuer", to_name(&info.issuer)?)?;

    d.set_item("version", info.version)?;
    d.set_item("serialNumber", info.serial_number.as_str())?;
    d.set_item("notBefore", info.not_before.as_str())?;
    d.set_item("notAfter", info.not_after.as_str())?;

    // subjectAltName: tuple of (kind, value) tuples. Only emit the key
    // when the extension is present, matching CPython.
    if !info.subject_alt_name.is_empty() {
        let entries: Vec<Py<PyTuple>> = info
            .subject_alt_name
            .iter()
            .map(|(k, v)| PyTuple::new(py, [k.as_str(), v.as_str()]).map(|t| t.unbind()))
            .collect::<PyResult<Vec<_>>>()?;
        let san = PyTuple::new(py, entries)?;
        d.set_item("subjectAltName", san)?;
    }

    Ok(d)
}

// Server-side SNI dispatch

/// Live, scoped view of an in-flight server handshake handed to the
/// `set_servername_callback` callable. Holds a raw `SSL*` that is only
/// valid for the duration of the callback - the dispatcher invalidates
/// the pointer on return so post-callback use raises rather than touching
/// a dangling handle.
#[pyclass(name = "SniHandshakeView", module = "_utls")]
struct PySniView {
    /// Live `SSL*` as `usize`, or 0 once the dispatcher invalidates it.
    /// `AtomicUsize` because `#[pyclass]` requires `Sync` and Python could
    /// theoretically expose the object to other threads (though the
    /// dispatcher invalidates synchronously, before returning the GIL).
    ssl: AtomicUsize,
    server_name: Option<String>,
}

#[pymethods]
impl PySniView {
    /// SNI host name the client sent, or `None` if absent.
    #[getter]
    fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Swap the in-flight SSL handle to use `new_ctx`. BoringSSL bumps the
    /// new `SSL_CTX`'s refcount and drops the previous one. Subsequent
    /// certificate selection, ALPN, verify mode, and TLS 1.3 cipher choice
    /// come from `new_ctx`.
    fn swap_context(&self, new_ctx: &PyContext) -> PyResult<()> {
        let raw = self.ssl.load(Ordering::SeqCst);
        if raw == 0 {
            return Err(PyRuntimeError::new_err(
                "SniHandshakeView is no longer valid (the callback has returned)",
            ));
        }
        // SAFETY: the raw value was stored from a `SniSslHandle` the
        // dispatcher was invoked with; the GIL serialises this method
        // against the trampoline's invalidation store after dispatch
        // returns.
        let handle = unsafe { core::SniSslHandle::from_raw(raw as *mut _) };
        new_ctx.inner.migrate_ssl(handle);
        Ok(())
    }
}

/// PyO3 implementation of [`core::SniDispatcher`]. Carries the user's
/// Python callable and dispatches by acquiring the GIL.
struct PySniDispatcher {
    cb: Py<PyAny>,
}

impl core::SniDispatcher for PySniDispatcher {
    fn dispatch(&self, handle: core::SniSslHandle, server_name: Option<&str>) -> core::SniAction {
        // SSL_AD_INTERNAL_ERROR per RFC 8446 §6.
        const ALERT_INTERNAL_ERROR: u8 = 80;
        let outcome: PyResult<core::SniAction> = Python::attach(|py| {
            let view = PySniView {
                ssl: AtomicUsize::new(handle.as_usize()),
                server_name: server_name.map(String::from),
            };
            let view_py = Py::new(py, view)?;
            let result = self.cb.bind(py).call1((view_py.clone_ref(py), server_name));
            // Invalidate the view's raw pointer regardless of outcome so a
            // user holding onto it cannot dereference a dead SSL handle.
            view_py.borrow(py).ssl.store(0, Ordering::SeqCst);
            let result = result?;
            if result.is_none() {
                Ok(core::SniAction::Ok)
            } else {
                let alert: u16 = result.extract().map_err(|_| {
                    PyTypeError::new_err("SNI callback must return None or an int TLS alert code")
                })?;
                if alert > 255 {
                    return Err(PyValueError::new_err(
                        "SNI callback alert code must fit in a byte (0..=255)",
                    ));
                }
                Ok(core::SniAction::Abort(alert as u8))
            }
        });
        match outcome {
            Ok(action) => action,
            Err(err) => {
                // Surface the Python exception on stderr (mirrors what
                // CPython does with stdlib's SNI callback) and abort the
                // handshake. We cannot let the exception propagate across
                // the FFI boundary.
                Python::attach(|py| err.print(py));
                core::SniAction::Abort(ALERT_INTERNAL_ERROR)
            }
        }
    }
}

#[pymodule]
fn _utls(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMemoryBio>()?;
    m.add_class::<PySession>()?;
    m.add_class::<PyFingerprint>()?;
    m.add_class::<PyContext>()?;
    m.add_class::<PyConnection>()?;
    m.add_class::<PySniView>()?;
    m.add("CoreError", py.get_type::<CoreError>())?;
    m.add("BORINGSSL_VERSION", core::boringssl_version())?;
    m.add("JA4_SPEC_VERSION", core::fingerprint::ja4::JA4_SPEC_VERSION)?;
    Ok(())
}

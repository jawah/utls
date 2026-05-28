BoringSSL-backed TLS for CPython, with Chrome impersonation
-----------------------------------------------------------

Drop-in replacement for the `ssl` stdlib with a `Fingerprint` API for Chrome
impersonation. Built on stock BoringSSL through `boring-sys` - no vendored
patches, no curl-impersonate, no Go runtime at import time. Use it with any
known Python http client you like or used to.

Supports CPython 3.7 onward, including freethreaded builds.

### Why this exists

We sat on this for a long time, kept it private as we needed to think
longer about whether the world really needed one more TLS library.

The initial thinking was: why do I have to install yet whole another
http client just because we need to look like a real browser? The
Python ecosystem already ships perfectly fine http clients - urllib3,
niquests, httpx, aiohttp - and all of them ride on top of `ssl`. If
the impersonation lives one layer down, in the SSL layer itself, every
one of them gets it for free. No fork of curl, no Go runtime imported
at module load, no second http client to teach your codebase, no
patched BoringSSL to maintain across CVE cycles.

That is what utls is: the ClientHello machinery, plugged in exactly
where the rest of Python already plugs in.

It was private until now. Enjoy it, but with care - browser
impersonation has legitimate uses (interop testing, anti-bot researches,
making sure your own service still answers a real Chrome correctly)
and it has illegitimate ones. The license forbids nothing; your
judgment does.

Contributions are welcome. New Chrome versions are one profile module
plus one registry line; platform fixes, bug reports and CI cleanups
are read and merged.

### Getting Started

Install from PyPI (pre-built wheels for Linux, macOS, and Windows):

```
pip install utls
```

Then swap `ssl` for `utls` anywhere in your code:

```python
import utls as ssl

ctx = ssl.create_default_context()
```

Or use it alongside the stdlib:

```python
from utls import SSLContext, PROTOCOL_TLS_CLIENT

ctx = SSLContext(PROTOCOL_TLS_CLIENT)
ctx.load_default_certs()

import socket
sock = socket.create_connection(("example.com", 443))
ssock = ctx.wrap_socket(sock, server_hostname="example.com")
ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print(ssock.recv(4096).decode())
```

It works with asyncio out of the box:

```python
import asyncio
import utls as ssl

async def main():
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.open_connection("example.com", 443, ssl=ctx)
    writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    await writer.drain()
    print((await reader.read(4096)).decode())
    writer.close()

asyncio.run(main())
```

### Browser impersonation

```python
import utls, socket

ctx = utls.create_default_context()
ctx.set_fingerprint("chrome:stable")

with socket.create_connection(("www.google.com", 443)) as raw:
    with ctx.wrap_socket(raw, server_hostname="www.google.com") as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
        print(s.recv(4096))
```

The bundled profile registry can be inspected at runtime:

```python
from utls import Fingerprint, presets

print(presets())
# ['chrome:131', 'chrome:142', 'chrome:146', 'chrome:148', 'chrome:stable']

fp = Fingerprint.from_preset("chrome:stable")
print(fp.ja3_hash, fp.ja4_hash)
```

Profiles ship as plain Python modules under `utls.profiles.*`. utls is
**Chrome-only by design**. Adding a new Chrome version is one `.py` file
plus one registry line.

#### What impersonation actually rewrites

`set_fingerprint` controls the **TLS ClientHello bytes**: cipher suite list
and order, extension list and order, named groups, key shares, signature
algorithms, ALPN/ALPS payloads, GREASE placement, certificate compression,
explicit ECH GREASE or real config, and so on. Everything that goes into a
JA3 or JA4 hash, utls drives.

What it does **not** rewrite, because they live above TLS:

- The HTTP request line, method, path, and body.
- HTTP/2 SETTINGS frames, WINDOW_UPDATE values, HEADERS frame priority
  flags, and the Akamai HTTP/2 fingerprint that some bot-detection
  vendors track. Those belong to your HTTP client; pair utls with
  `niquests` or `urllib3-future` if you need them honored end-to-end.

#### Carrying the canonical Chrome header set

Each profile also publishes the exact HTTP request-header set Chrome sends
on a top-level navigation, in the on-the-wire insertion order. The HTTP
layer is yours to drive, but the headers are right there if you want
matched cosmetics:

```python
from utls import Fingerprint

fp = Fingerprint.from_preset("chrome:stable")
for name, value in fp.http_headers.items():
    print(f"{name}: {value}")
# sec-ch-ua: "Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"
# sec-ch-ua-mobile: ?0
# sec-ch-ua-platform: "Linux"
# User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ...
# Accept: text/html,application/xhtml+xml,...
# ...
```

Request- or session-dependent headers (`Host`, `Cookie`, `Referer`,
`Content-Length`, `Content-Type`, plus H2 pseudo-headers) are deliberately
omitted from the dict; the HTTP client is responsible for emitting those.
For HTTP/1.1, prepend `Host` at position 0 to preserve Chrome's wire order.

#### Choosing a profile

- `chrome:stable` always tracks the newest Chrome major shipped in a utls
  release. Use this if you want to drift with Chrome without code changes.
- `chrome:148`, `chrome:146`, `chrome:142`, `chrome:131` pin to specific
  Chrome majors. Use these when reproducibility matters - e.g. a long-
  running scraper that should not silently change shape when utls is
  upgraded.

The JA4 hash is the fingerprint identity that bot-detection vendors and
TLS observatories actually index on. `chrome:142` / `chrome:146` /
`chrome:148` share the same JA4 because they share the same TLS-layer
ClientHello (the deltas are HTTP-layer); `chrome:131` differs because it
uses the legacy ALPS codepoint (`0x4469` vs `0x44cd`).

#### Why JA3 varies but JA4 stays put

Chrome 110+ permutes its TLS extension order on every connection to defeat
order-based fingerprinting. utls mirrors that behavior. As a result:

- **JA3** hashes the wire order verbatim, so `fp.ja3_hash` (and the
  hash you'd compute from a live capture) shifts per connection. Use the
  JA3 *string* for diffing the extension set, not the hash for equality.
- **JA4** sorts extension codepoints before hashing, so `fp.ja4_hash`
  is stable and the value that matches your live capture.

#### Capturing a fingerprint from a live ClientHello

If you have raw ClientHello bytes (e.g. captured via tcpdump, mitmproxy,
or a custom TLS trap), you can rebuild a `Fingerprint` from them and feed
it back into a context:

```python
from utls import Fingerprint, SSLContext

raw = open("clienthello.bin", "rb").read()
fp = Fingerprint.from_capture(raw)
print(fp.ja4_hash)

ctx = SSLContext()
ctx.set_fingerprint(fp)
```

Captured fingerprints carry no HTTP headers (`fp.http_headers == {}`);
they only encode the TLS layer. To round-trip a full profile, use
`fp.to_dict()` + `Fingerprint.from_dict(...)` and add `http_headers`
manually.

#### Server-side and impersonation

`set_fingerprint` on a server-side context raises at the Rust level. The
ClientHello is, by definition, the client's choice; a server-side
fingerprint would be meaningless on the wire. Server contexts can still
**inspect** the peer ClientHello for diagnostics (see the Server-side
section below).

### Encrypted Client Hello (ECH)

Chrome profiles ship with ECH **GREASE** enabled by default, matching real
Chrome. To offer *real* ECH - encrypting the inner ClientHello (including
the real SNI) under the server's published HPKE config - fork a per-peer
context carrying the wire-format `ECHConfigList` bytes:

```python
import utls, socket

base = utls.SSLContext()
base.load_default_certs()
base.set_fingerprint("chrome:stable")

# ECH configs are peer-specific* - each origin publishes its own in a DNS
# HTTPS RR. `set_ech_configs` is non-mutating: it returns a NEW SSLContext
# that shares the underlying SSL_CTX (and CA store) with `base` via
# SSL_CTX_up_ref, so the fork is cheap. `base` is untouched and can be
# re-forked for other peers.
ech_bytes = ...  # you are responsible to get it yourself!
ctx = base.set_ech_configs(ech_bytes)

with socket.create_connection(("example.com", 443)) as raw:
    ssl_sock = ctx.wrap_socket(raw, server_hostname="example.com")
    ssl_sock.do_handshake()
```

utls does **not** perform the DNS HTTPS RR lookup; the caller fetches the
`ech=` bytes (e.g. via `dnspython`'s `HTTPS` rdata). Pass `None` to clear
the ECH override in the fork.

Niquests or urllib3-future does ECH transparently via a custom resolver (E.g. DNS over HTTPS) No effort required.

### Feature parity with stdlib

utls re-exports the public names of the `ssl` module that matter for client
*and* server code paths. The Python facade is a real subclass of
`ssl.SSLContext`, so `isinstance(ctx, ssl.SSLContext)` is true and most
downstream libraries (urllib3-future, niquests, httpx with custom
transports) accept a utls context directly.

**What's different from `ssl`:**

- TLS 1.2 is the minimum version. SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are
  not available - BoringSSL refuses to negotiate them (No decent client out there should try < TLS 1.2).
- Hostname verification uses SAN only, never the Common Name.
- `compression()` always returns `None` (TLS compression is disabled, as
  it should be - BoringSSL doesn't ship it - as anyone should).
- PSK callbacks are not available - BoringSSL deleted them upstream.
- A `Fingerprint` API exists and is honored on the client side.
  Server-side `set_fingerprint` rejects at the Rust level: the
  ClientHello is the client's choice, not the server's.

### Server-side

Server-side TLS is supported for everything BoringSSL still exposes:

- mTLS (client certificate auth via `verify_mode=CERT_REQUIRED`),
- ALPN selection from a server preference list,
- SNI dispatch via `set_servername_callback`,
- ECDH curve restriction (`set_ecdh_curve`),
- Session ticket count (`set_num_tickets`),
- `set_session_id_context`,
- Server-side ClientHello fingerprinting (read-only diagnostics).

Things you can't have on the server side because BoringSSL doesn't have
them: DTLS, FFDHE parameters, SSLv2/SSLv3, TLS compression, PSK.

### urllib3-future / niquests

utls is automatically picked up if installed. enjoy.

### Disclaimer

Early/Beta project. The public API is stable; we do not plan to diverge
from stdlib for the `ssl`-compatible subset. Not pure Python - you need
either a pre-built wheel or a build environment (Rust + cmake + ninja +
Go for BoringSSL).

MIT-licensed (see `LICENSE`). BoringSSL is permissively licensed;
`boring-sys` is Apache-2.0 - bundled into the wheel.

- FIPS mode is not on the roadmap.
- Chrome only. Firefox / Safari / Edge are unlikely. Thus, contribution are welcomed.
- PyPy is not supported.

Throughput is on par with stdlib `ssl`: ~343 MiB/s for bulk recv vs.
stdlib's 340 MiB/s on a loopback TLS 1.3 / AES-256-GCM connection.
(yes, it is faster than rtls!)

Contributions, bug reports and feedback are welcome.

### Versioning

This project uses [CalVer](https://calver.org/) (`YYYY.0M.0D`). It aims
to be a drop-in replacement for stdlib `ssl`, so semantic versioning
would be misleading - pin a lower bound, not an upper bound.

### Prior art

- [`rtls`](https://github.com/jawah/rtls) - same drop-in approach over
  rustls. utls's MemoryBIO-first design and read-batching pass are
  directly inspired by it; many of the compatibility tests were
  ported from there.
- [`uTLS`](https://github.com/refraction-networking/utls) - the
  reference Go-language TLS fingerprinting library. The spec data
  encoded in our Chrome profiles is checked against uTLS's published
  ClientHellos.
- [`curl-impersonate`](https://github.com/lwthiker/curl-impersonate) -
  the original "browser-on-the-wire" project. utls aims to give Python
  the same capability without a non-native Python http client or a patched BoringSSL.

### JA4 pinning

The JA4 fingerprint algorithm is pinned to FoxIO-LLC/ja4 spec revision
`0.18.8`. The constant is duplicated in `python/utls/_fingerprint.py`
(`JA4_SPEC_VERSION`) and `crates/utls-core/src/fingerprint/ja4.rs`, and a
dedicated CI job asserts they agree.

### Documentation

For the `ssl`-compatible surface, the stdlib documentation at
<https://docs.python.org/3/library/ssl.html> applies almost verbatim - the
notable exceptions are listed under [Feature parity with stdlib](#feature-parity-with-stdlib).

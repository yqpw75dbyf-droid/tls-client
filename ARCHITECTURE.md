# Architecture

This document describes what the repository contains and how a request flows
through it, from the Go library, through the browser fingerprint profiles, to
the C shared library and the Python package.

## What this is

A Go HTTP client that sends requests with a **real browser's TLS and HTTP/2
fingerprint**, so that a server cannot tell the client apart from Chrome,
Firefox, Safari, Opera, Edge, or Tor Browser at the handshake layer. Changing
the `User-Agent` header is not enough: servers fingerprint the TLS ClientHello
(cipher order, extensions, key shares → JA3/JA4) and the HTTP/2 preamble
(SETTINGS frame, window update, header-frame priority, pseudo-header order →
the Akamai fingerprint). This client reproduces all of those from captured
browser data.

It is a fork of `bogdanfinn/tls-client`, republished as
`github.com/yqpw75dbyf-droid/tls-client`, and it drives four sibling forks that
do the low-level work:

| Dependency | Role |
|---|---|
| `bogdanfinn/utls` | Custom TLS ClientHello (the JA3/JA4 surface) |
| `bogdanfinn/fhttp` | Fork of net/http with header ordering, custom H2 SETTINGS/priority, stream id |
| `bogdanfinn/quic-go-utls` | HTTP/3 with a QUIC fingerprint |
| `bogdanfinn/websocket` | WebSocket over the same fingerprinted TLS dialer |

## Directory map

```
.
├── client.go              HttpClient interface, Do(), pre/post hooks, debug dump
├── client_options.go      every WithXxx(...) option and the config struct
├── roundtripper.go        the core: dial TLS, read ALPN, build the right transport
├── racer.go               HTTP/3 vs HTTP/2 "happy eyeballs" racing
├── connect.go             proxy dialers: direct, HTTP CONNECT, SOCKS4, SOCKS5
├── socks5_udp.go          SOCKS5 UDP ASSOCIATE, so HTTP/3 can tunnel through a proxy
├── jar.go                 cookie jar with GetAllCookies and host-key bucketing
├── pinner.go              certificate pinning (HPKP)
├── ja3.go                 build a ClientHelloSpec from a JA3 string (custom profiles)
├── mapper.go              name → utls constant tables (ciphers, curves, sig algs, H2/H3 settings)
├── logger.go              Logger interface: noop, info, debug
├── utils.go               int conversion, GREASE H3 setting id/value generators
├── websocket.go           WebSocket wrapper reusing the client's TLS dialer
│
├── profiles/              the browser fingerprint database (see below)
├── bandwidth/             per-connection byte counting (read/write totals)
├── cffi_src/              the C-shared-library glue: factory + request/response types
├── cffi_dist/             the buildable C shared library (main.go, build.sh, examples)
├── python/                the Python package wrapping the shared library
├── example/               runnable Go examples, one directory per feature
└── tests/                 23 integration tests (network + behaviour)
```

## Request lifecycle (Go)

```
NewHttpClient(logger, opts...)                              client.go
  ├─ apply options → httpClientConfig                       client_options.go
  ├─ validateConfig (proxy/racing/IP-stack consistency)     client.go
  └─ buildFromConfig                                        client.go
       ├─ dialer  = direct | CONNECT | socks4 | socks5 | custom   connect.go
       ├─ transport = newRoundTripper(profile, ...)               roundtripper.go
       └─ &http.Client{Transport, Timeout, CheckRedirect}

client.Do(req)                                             client.go
  ├─ executePreHooks(req)                                  (abort on error)
  ├─ lowercase req[HeaderOrderKey]                         (ordering is case-sensitive)
  ├─ optional debug dump of request bytes
  ├─ http.Client.Do(req)  ──────────────►  roundTripper.RoundTrip
  └─ executePostHooks(req, resp, err)                      (always runs)
```

### The round tripper — the clever part (`roundtripper.go`)

The client does not hand the request straight to a fixed transport. It dials
TLS first, looks at what protocol the server negotiated over ALPN, and only
then builds the matching transport:

```
RoundTrip(req)
  ├─ racing enabled and https?  → racer.race(...)          racer.go
  └─ otherwise:
       getTransport(addr)  (once per address, under a lock)
         ├─ dialTLSSetup: dial TCP → wrap for bandwidth → utls handshake
         ├─ certificatePinner.Pin(conn, host)
         ├─ inspect conn.ConnectionState().NegotiatedProtocol
         │     "h2"       → http2.Transport with the profile's SETTINGS/priority
         │     "h3"       → http3.Transport (buildHTTP3Transport)
         │     else       → http.Transport (HTTP/1.1)
         ├─ cache the transport AND its "kind" for this address
         └─ stash the just-handshaked connection for the first request
       t.RoundTrip(req)
         └─ if the server later negotiates a different protocol on a
            reconnect (load balancer changed its mind), dialTLS returns
            errProtocolChanged; RoundTrip drops the cached transport and
            rebuilds. Without this an H1 transport reading an H2 SETTINGS
            frame fails forever for that address.
```

Two mutexes guard the caches because the first dial runs with the transport
lock held (through `getTransport`) while reconnects dial from inside the
transport's own goroutine with no lock. `cachedKinds` records which transport
kind serves each address so a reconnect can tell whether the newly negotiated
protocol still fits.

### Protocol racing (`racer.go`)

With `WithProtocolRacing()`, the client mimics Chrome's "happy eyeballs": it
starts an HTTP/3 (QUIC) attempt and, after a 300 ms delay, an HTTP/2 (TCP)
attempt, and uses whichever connects first. The winning protocol is cached per
host. Racing requires a SOCKS5 proxy or no proxy, because only SOCKS5 can
tunnel the QUIC/UDP traffic (`socks5_udp.go`); any other proxy scheme is
rejected at config validation so HTTP/3 cannot leak the real IP.

## The profile database (`profiles/`)

A profile is a `ClientProfile`: a `utls.ClientHelloID` (the TLS spec) plus the
HTTP/2 half (SETTINGS map and order, connection flow, pseudo-header order,
first stream id, header-frame priority) and optional HTTP/3 settings.

```
profiles.go                     MappedTLSClients: identifier string → ClientProfile
                                (150 entries; the registry the CFFI layer looks up)
internal_browser_profiles.go    Chrome, Firefox, Safari desktop/iOS, base Opera
contributed_browser_profiles.go community-contributed Chrome/Firefox/Brave
chrome_profiles.go              Chrome 153 + Edge relabel helper input
edge_profiles.go                Edge 153 (Chrome 152 minus trust_anchors)
opera_profiles.go               Opera 92–136 (relabelled Chrome by Chromium base)
safari_macos_profiles.go        Safari macOS 15.3–26.6 (relabelled iOS captures)
tor_profiles.go                 Tor Browser 14.x, 15 (Firefox ESR minus resumption)
firefox_profiles.go             resumption-trail helper for older Firefox specs
extension_data.go               trust_anchors (0xca34) captured payloads + shuffling
grease.go                       random GREASE signature scheme per connection
internal_custom_profiles.go     app profiles (Nike, Zalando, MMS, Mesh, okhttp, ...)
contributed_custom_profiles.go  more app profiles
ja3.go (repo root)              GetSpecFactoryFromJa3String: build a spec from JA3
```

**How profiles relate.** Most non-Chrome browsers share an engine with a
Chrome or Firefox already captured here, so their profiles are built by
relabelling the base rather than copying its spec:

- **Opera** is Chromium. `operaProfile(version, base)` reuses a Chrome
  profile's spec and H2 settings, choosing the base by Chromium feature
  milestones (Opera N ≈ Chromium N+14, drifting to +15 then +16 where Opera
  skipped Chromium 129 and 136).
- **Edge** is Chromium with Microsoft's root store, so `Edge_153` is
  `Chrome_152` with the `trust_anchors` extension removed.
- **Safari macOS** shares Apple's stack with Safari iOS byte-for-byte, so the
  macOS profiles relabel the iOS captures, overriding only the H2 window where
  the desktop differed (17.x) before the platforms converged (18+).
- **Tor Browser** is Firefox ESR with `session_ticket` and
  `psk_key_exchange_modes` stripped; that removal is its signature.

The relabelling helper (`derivedHelloID`) pins the spec to the **source**
ClientHelloID. Profiles that name a utls built-in carry an empty spec factory
and are resolved by utls from the `"Client-Version"` string; renaming the
client without pinning would make that lookup miss and fail at handshake. The
per-profile `*_test.go` files verify each derived profile matches its base on
the wire, and `TestNoH3InTCPClientHello` guards the whole registry against a
capture mistake (h3 in a TCP ClientHello) that only shows with HTTP/3 enabled.

## Bandwidth tracking (`bandwidth/`)

`Tracker` holds two atomic counters. `TrackConnection` wraps a `net.Conn` in a
`BTConn` whose `Read`/`Write` add to the counters, so bytes are counted at the
raw TCP layer — including the TLS handshake, and before decompression.
`NopeTracker` is the zero-cost default when `WithBandwidthTracker()` is off, so
the round tripper can always call `TrackConnection` without a branch. Counters
are client-wide across all requests and hosts; `Reset()` to measure one call.

## The C shared library (`cffi_src/`, `cffi_dist/`)

`cffi_dist/main.go` compiles with `-buildmode=c-shared` into a `.so`/`.dll`/
`.dylib` that exports six C functions, so any language with an FFI can drive
the Go core over JSON:

| Export | Does |
|---|---|
| `request` | build a client + do one request, return a JSON response |
| `getCookiesFromSession` | read a session's cookie jar for a URL |
| `addCookiesToSession` | inject cookies into a session |
| `destroySession` | drop one session's client and close its connections |
| `destroyAll` | drop every session |
| `freeMemory` | free the C string a previous call returned, by its response id |

`cffi_src/factory.go` turns a `RequestInput` (JSON, defined in
`cffi_src/types.go`) into a real `HttpClient`, caching one client per
`sessionId` so cookies and connections persist across calls. `cffi_src/types.go`
is the wire contract: `RequestInput`, `CustomTlsClient`, `Cookie`, `Response`.
Returned C strings are kept alive in a Go map keyed by response id and must be
released with `freeMemory` — every caller that reads a result frees it.

## The Python package (`python/`)

A pip-installable package with a `requests`-style API and httpcloak-style
top-level helpers, wrapping the shared library through `ctypes`.

```
python/
├── pyproject.toml            package metadata; bundles dependencies/*.so|dll|dylib if present
├── README.md                 install, build the lib, API reference, usage rules
├── examples/basic.py
└── tls_client/
    ├── __init__.py           exports Session, Response, get/post/..., CLIENT_IDENTIFIERS
    ├── cffi.py               locate + load the shared library, wire the 6 C functions
    ├── settings.py           the 150 client identifiers, mirrored from profiles.go
    ├── response.py           requests-shaped Response, plus .protocol
    └── sessions.py           Session class, JSON marshalling, memory freeing, helpers
```

### Python request flow

```
tls_client.get(url, preset="chrome_153")            module-level helper
  └─ Session(preset=...)                             validate identifier vs CLIENT_IDENTIFIERS
       └─ Session.request("GET", url, ...)
            ├─ build query string from params
            ├─ encode body: json → JSON, dict → form, bytes → base64 byte-request
            ├─ merge session + per-request headers
            ├─ assemble the RequestInput dict (sessionId, identifier, headers,
            │  headerOrder, proxy, redirects, timeout, http toggles, ...)
            ├─ cffi.request(json.dumps(payload))     ─► Go core
            ├─ parse JSON reply, cffi.free_memory(reply["id"])
            └─ Response(reply)   → .status_code, .text, .protocol, .headers, .cookies, .json()
```

The shared library is **not** bundled (building it needs cgo and a C
toolchain). `cffi.py` finds it via the `TLS_CLIENT_LIBRARY` environment
variable, a `tls_client/dependencies/` directory, or the working directory,
and raises a clear build command if none is found.

## Building and running

```bash
# Go library — used directly as a module
go test ./...

# C shared library — for the Python/Node/C# bindings
cd cffi_dist
CGO_ENABLED=1 go build -buildmode=c-shared -o dist/tls-client.so .   # .dll / .dylib per OS

# Python package
pip install ./python
export TLS_CLIENT_LIBRARY=$PWD/cffi_dist/dist/tls-client.so
python python/examples/basic.py
```

## Usage rules that are easy to get wrong

- **Chromium profiles (Chrome, Opera, Edge):** enable
  `WithRandomTLSExtensionOrder()`. Real Chrome shuffles its extension order
  every connection; a fixed order is a tell.
- **Safari and Tor:** do **not** shuffle — those engines never do.
- **Tor:** route through the Tor daemon and disable HTTP/3. A Tor Browser
  fingerprint from a non-Tor IP is worse than not impersonating Tor at all.
- **Every profile:** the request headers must tell the same story as the TLS
  layer — the right `User-Agent`, the matching `sec-ch-ua` (or none, for
  Firefox/Safari/Tor, which have no client hints), and the browser's real
  header order.

# tls_client (Python)

Python bindings for this repo's Go core, with a `requests`-style API and
httpcloak-style top-level helpers. Every request goes out with a real
browser's TLS and HTTP/2 fingerprint.

```python
import tls_client

r = tls_client.get("https://tls.peet.ws/api/all", preset="chrome_153")
print(r.status_code, r.protocol)          # 200 HTTP/2.0

with tls_client.Session(preset="firefox_135") as s:
    s.get("https://example.com")           # cookies + connections persist
```

## Install

```bash
pip install ./python          # from the repo root
```

The package is pure Python. It drives a compiled Go shared library, which is
**not** bundled (building it needs cgo and a C toolchain). Build it once:

```bash
cd cffi_dist
CGO_ENABLED=1 go build -buildmode=c-shared -o dist/tls-client.so .   # Linux
# Windows: -o dist/tls-client.dll   macOS: -o dist/tls-client.dylib
```

Then let Python find it, any one of:

- set `TLS_CLIENT_LIBRARY=/path/to/tls-client.so`;
- copy the file into `python/tls_client/dependencies/`;
- run your script from a directory that contains it.

## API

Top-level `get`, `post`, `put`, `patch`, `delete`, `head`, `options` take a
`preset=` (a client identifier) and the same keyword arguments as
`Session.request`.

`Session(preset="chrome_153", ...)` keeps one Go client alive: its cookie jar,
its connections, its TLS session cache. Reuse it for anything that should look
like one browsing session.

### Random presets and automatic headers

`preset` also takes a family name or `"random"`, like primp's
`impersonate="random"`. The pick happens once per Session, from the family's
five newest releases (an old Chrome in today's traffic is a tell, not variety):

```python
tls_client.Session(preset="chrome")      # one of chrome_144 … chrome_153
tls_client.Session(preset="safari")      # a recent Safari macOS
tls_client.Session(preset="random")      # chrome / edge / opera / firefox / safari
```

Families: `chrome`, `chromium`, `edge`, `brave`, `opera`, `firefox`, `tor`,
`safari`, `safari_ios`, `safari_ipad` (`tls_client.BROWSER_FAMILIES`).

Every browser preset, random or not, starts with the real browser's navigation
headers in the real order: `user-agent`, `accept`, `accept-encoding`,
`accept-language`, the `sec-fetch-*` set, `priority`, `te` for Firefox/Tor,
and for Chromium the `sec-ch-ua` trio computed with Chromium's own brand
algorithm (`"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`
for Chrome 153; `OPR/` and `"Opera"` for Opera on its Chromium base; `Edg/`
and `"Microsoft Edge"` for Edge). Your `headers=` override by name, your
`header_order=` wins outright, and `default_headers=False` turns the whole
thing off. `tls_client.browser_headers("opera_125")` returns the set for
inspection.

### Request arguments

| argument | meaning |
|---|---|
| `params` | dict appended as the query string |
| `data` | str, bytes, or dict (form-encoded); bytes are sent as a byte request |
| `json` | any JSON-serialisable value; sets `Content-Type: application/json` |
| `headers` | per-request headers, merged over the session's |
| `cookies` | dict of cookies for this request |
| `allow_redirects` | follow redirects (default `True`) |
| `proxy` | `http://user:pass@host:port` or `socks5://host:port` |
| `timeout_seconds` | per-request timeout |
| `insecure_skip_verify` | skip certificate verification |

### Session options

`preset` / `client_identifier`, `headers`, `header_order`, `proxy`,
`timeout_seconds`, `force_http1`, `disable_http3`, `disable_session_tickets`,
`random_tls_extension_order`, `protocol_racing`, `catch_panics`, `debug`.

Header order is part of the fingerprint. Set `header_order` to the exact lower
case order the browser you are impersonating sends.

### Custom fingerprint

Pass `ja3_string=...` (plus optional `h2_settings`, `h2_settings_order`,
`supported_signature_algorithms`, `supported_versions`, `key_share_curves`,
`cert_compression_algo`, `pseudo_header_order`, `connection_flow`) instead of a
preset to build a profile from a captured fingerprint.

## Profiles

`tls_client.CLIENT_IDENTIFIERS` is the full set. It includes Chrome through
153, Edge 153, Firefox through 148, Safari macOS 15.3–26.6 and iOS, Opera
92–136, Tor Browser 14.x and 15, Brave, and the app profiles (Nike, Zalando,
okhttp, and so on).

Three usage rules that are easy to get wrong:

- **Headers are half the fingerprint.** A perfect Chrome TLS hello attached
  to Go's default `user-agent: Go-http-client/2.0` is flagged at the header
  layer before TLS is even inspected. The Session sets the browser's real
  headers and order for you (see above); if you pass `default_headers=False`
  or drive the C library directly, set `User-Agent`, `sec-ch-ua` (Chromium
  only), `accept-encoding` including `zstd` for Chrome 123+, and the real
  `header_order` yourself.
- **Extension shuffle is automatic per engine.** Chromium presets (`chrome_`,
  `opera_`, `edge_`, `brave_`) shuffle TLS extension order every connection,
  as the real browser does; Safari, Firefox and Tor never do, so their presets
  don't. Pass `random_tls_extension_order=True/False` only to override.
- **Tor:** route through the Tor daemon (`proxy="socks5://127.0.0.1:9150"` for
  Tor Browser's own, `9050` for a standalone `tor`) and set
  `disable_http3=True`. A Tor fingerprint from a non-Tor IP is worse than none.
```

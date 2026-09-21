# TLS-Client

A Go HTTP client that sends requests with a **real browser's TLS and HTTP/2
fingerprint**. Changing the `User-Agent` is not enough — servers fingerprint
the TLS ClientHello (cipher and extension order, key shares → JA3/JA4) and the
HTTP/2 preamble (SETTINGS, window update, header priority, pseudo-header order
→ the Akamai fingerprint). This client reproduces both from captured browser
data, so at the handshake layer it is indistinguishable from the browser it
impersonates.

This is a fork of [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client),
published as `github.com/yqpw75dbyf-droid/tls-client`. It builds on
[fhttp](https://github.com/bogdanfinn/fhttp) and
[utls](https://github.com/bogdanfinn/utls).

For the full design and request flow, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## What this fork adds

- **Opera 92–136** — the full modern line, mapped to the right Chromium base
  (the offset drifts +14 → +15 → +16 where Opera skipped Chromium 129 and 136).
- **Safari macOS 15.3–26.6** — every point release, grouped by the handshake
  era it belongs to, with the desktop HTTP/2 differences from iOS.
- **Tor Browser 14.0, 14.5, 15.0** — 15.0 captured from a real install over a
  live Tor circuit.
- **Chrome 153 and Edge 153** — captured from the real browsers; Edge is
  Chrome 152 without the `trust_anchors` extension.
- **Firefox repairs** — the profiles now carry the resumption extensions and
  the real HTTP/2 header-frame priority, instead of accidentally wearing Tor's
  shape and Chrome's H2 priority.
- **A Python package** — `import tls_client; tls_client.get(url, preset=...)`,
  see [python/](./python/).
- Fingerprint fixes verified on the wire, and per-profile tests that fail if a
  profile drifts from the browser it names.

## Features

- HTTP/1.1, HTTP/2, HTTP/3 with automatic protocol selection
- Protocol racing (Chrome-style happy eyeballs for HTTP/2 vs HTTP/3)
- TLS fingerprinting for Chrome, Firefox, Safari, Edge, Opera, Brave, Tor, and
  mobile app clients
- Custom fingerprints from a JA3 string plus HTTP/2 and HTTP/3 parameters
- WebSocket over the same fingerprinted TLS dialer
- Custom header ordering
- HTTP and SOCKS4/SOCKS5 proxies (SOCKS5 UDP for HTTP/3)
- Cookie jar management
- Certificate pinning
- Bandwidth tracking
- Language bindings via a C shared library: Python, Node.js, C#

## Install (Go)

```bash
go get github.com/yqpw75dbyf-droid/tls-client@latest
```

## Quick start (Go)

```go
package main

import (
	"fmt"
	"io"
	"log"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/yqpw75dbyf-droid/tls-client"
	"github.com/yqpw75dbyf-droid/tls-client/profiles"
)

func main() {
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_153),
		tls_client.WithRandomTLSExtensionOrder(), // Chromium shuffles per connection
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header = http.Header{
		"accept":          {"*/*"},
		"accept-language": {"en-US,en;q=0.9"},
		"user-agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"},
		http.HeaderOrderKey: {"accept", "accept-language", "user-agent"},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.StatusCode)
	fmt.Println(string(body))
}
```

## Quick start (Python)

```python
import tls_client

r = tls_client.get("https://tls.peet.ws/api/all", preset="chrome_153")
print(r.status_code, r.protocol)

with tls_client.Session(preset="firefox_135") as s:
    s.get("https://example.com")
```

The Python package drives a compiled C shared library that is not bundled;
[python/README.md](./python/README.md) covers building it and the full API.

## Profiles

`profiles.MappedTLSClients` (Go) and `tls_client.CLIENT_IDENTIFIERS` (Python)
list every identifier: Chrome 103–153, Edge 153, Firefox 102–148, Safari macOS
15.3–26.6 and iOS, Opera 89–136, Tor Browser 14.x/15, Brave, and app profiles
(Nike, Zalando, MMS, Mesh, okhttp, and others).

### Getting a profile right

The handshake is only half of looking like a browser. Match the rest too:

- **Chromium (Chrome, Opera, Edge):** enable `WithRandomTLSExtensionOrder()` —
  real Chrome shuffles its extension order every connection.
- **Safari and Tor:** do **not** shuffle; those engines never do.
- **Tor:** route through the Tor daemon (`socks5://127.0.0.1:9150` for Tor
  Browser, `9050` for a standalone `tor`) and disable HTTP/3. A Tor
  fingerprint from a non-Tor IP is worse than not impersonating Tor.
- **Every profile:** send headers that tell the same story — the right
  `User-Agent`, the matching `sec-ch-ua` (or none, for Firefox/Safari/Tor,
  which have no client hints), and the browser's real header order. The
  Python `Session` does this automatically for every browser preset, and
  accepts a family name or `"random"` to pick a recent version per session;
  Go callers set the headers themselves.

## Language bindings

The Go core compiles to a C shared library (`cffi_dist/`) that exposes
`request`, `getCookiesFromSession`, `addCookiesToSession`, `destroySession`,
`destroyAll`, and `freeMemory` over JSON. Examples for Python, Node.js, C#, and
TypeScript are in `cffi_dist/`.

```bash
cd cffi_dist
CGO_ENABLED=1 go build -buildmode=c-shared -o dist/tls-client.so .   # .dll / .dylib per OS
```

## Testing

Test files are kept local only and are not published to the module: `*_test.go`
and the `tests/` integration suite are git-ignored. They still run in a local
checkout.

```bash
go test ./...                 # library + profile tests
# tests/ integration suite needs a SOCKS_5_PROXY env var for the proxy tests
```

## Credits and license

Fork of `bogdanfinn/tls-client`, itself built on the work of Carcraftz and the
[refraction-networking/utls](https://github.com/refraction-networking/utls)
project. MIT licensed; see [LICENSE](./LICENSE).

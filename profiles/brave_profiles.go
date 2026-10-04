package profiles

// Brave 154 sends Edge 154's handshake: Chrome's hello without the
// trust_anchors extension.
//
// Measured on this machine's Brave 1.96.61 (Chromium 154) on Windows, five
// fresh headless processes driven over DevTools against tls.peet.ws/api/all
// on 2026-10-04:
//
//   - JA4 t13d1516h2_8daaf6152771_806a8c22fdea and peetprint
//     8f568b2a409b82d0ec24cb84bf3bc3fc on every run, the Edge_154 values; JA3
//     differed per run, as the extension shuffle makes it
//   - the Chrome_152 extension set without trust_anchors (51764), between two
//     GREASE extensions
//   - signature_algorithms opening with a GREASE value, then ML-DSA 0x0904,
//     0x0905, 0x0906, then the classic eight; Brave_146 had neither
//   - ECH GREASE with HKDF-SHA256 and AES-128-GCM, payloads of 144 to 240
//     bytes drawn per connection
//   - HTTP/2 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p, HEADERS on
//     stream 1 with weight 256 exclusive
//
// A second navigation in the same session resumed with a PSK twice: JA4
// t13d1517h2_8daaf6152771_a87ad97598a9, peetprint
// a82a2c4591e2920411e95d5375bab512, pre_shared_key last after the second
// GREASE extension, which is Chrome_152_PSK without trust_anchors.
//
// The headers real Brave 154 sent, for callers: sec-ch-ua "Chromium";v="154",
// "Brave";v="154", "Not A(Brand";v="99"; Chrome's user agent with no Brave
// token; sec-gpc: 1 right after accept; and an accept-language whose q value
// Brave varies per session (en-US,en;q=0.7 four times, q=0.8 once). The order
// was sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
// upgrade-insecure-requests, user-agent, accept, sec-gpc, sec-fetch-site,
// sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding,
// accept-language, priority.
var (
	Brave_154 = func() ClientProfile {
		profile := Chrome_152
		profile.clientHelloId = helloIDWithoutExtension("Brave", "154", Chrome_152.clientHelloId, extensionTrustAnchorsID)

		return profile
	}()

	Brave_154_PSK = func() ClientProfile {
		profile := Chrome_152_PSK
		profile.clientHelloId = helloIDWithoutExtension("Brave", "154_PSK", Chrome_152_PSK.clientHelloId, extensionTrustAnchorsID)

		return profile
	}()
)

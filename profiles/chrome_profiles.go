package profiles

import (
	tls "github.com/bogdanfinn/utls"
)

// Chrome 153 (stable 2026-09-08, the first release on Chrome's two week
// cadence) changed nothing in the handshake. Measured on this machine's
// branded Chrome 153.0.8010.48 on Windows, driven headless (--headless=new)
// against tls.peet.ws/api/all three times on 2026-09-20:
//
//   - JA4 t13d1517h2_8daaf6152771_cb7bf5808d99 on every run, which is the
//     JA4 the Chrome_152 profile measures; JA3 differed per run, as the
//     extension shuffle makes it
//   - the same 17 extensions: server_name, ec_point_formats, key_share,
//     extended_master_secret, session_ticket, status_request, ECH GREASE,
//     application_settings (17613, h2), trust_anchors (51764),
//     psk_key_exchange_modes, SCT, supported_groups, supported_versions,
//     compress_certificate (brotli), signature_algorithms, ALPN (h2,
//     http/1.1), renegotiation_info, between two GREASE extensions
//   - signature_algorithms opening with a GREASE value, then the ML-DSA
//     codepoints 0x0904, 0x0905, 0x0906, then the classic eight
//   - key shares GREASE, X25519MLKEM768, X25519
//   - the trust_anchors payload: 186 bytes, the same 28 anchor IDs as the
//     Chrome 152 capture in extension_data.go, in a different order, which
//     is Chromium's per process hash set order and what the shuffle at
//     package load reproduces
//   - no server_padding (0x12e0). bogdanfinn/tls-client issue 281 reports
//     it in a Chrome for Testing 152 build; branded stable 153 does not send
//     it, so the profile stays without it
//   - HTTP/2 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p, HEADERS
//     on stream 1 with weight 256 exclusive, which is also the transport
//     default
//
// So Chrome_153 is Chrome_152 relabelled, the way Opera relabels Chrome.
// The request headers real Chrome 153 sent, for callers building the rest of
// the story: sec-ch-ua "Google Chrome";v="153", "Not_A Brand";v="8",
// "Chromium";v="153", then sec-ch-ua-mobile, sec-ch-ua-platform,
// upgrade-insecure-requests, user-agent, accept, sec-fetch-site,
// sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding "gzip,
// deflate, br, zstd", accept-language, priority "u=0, i".
//
// Chrome 154 (stable 2026-09-22) changed exactly one thing in the handshake:
// the order of the trust_anchors IDs. Measured on this machine's branded
// Chrome 154.0.8037.58 on Windows, driven headless against
// tls.peet.ws/api/all from five separate processes on 2026-10-02:
//
//   - JA4 t13d1517h2_8daaf6152771_cb7bf5808d99 on every run, the Chrome_152
//     and Chrome_153 JA4; JA3 differed per run, as the shuffle makes it
//   - the same 17 extensions, 16 cipher suites, signature algorithms (GREASE
//     first, then ML-DSA 0x0904, 0x0905, 0x0906, then the classic eight),
//     supported groups and key shares (GREASE, X25519MLKEM768, X25519) as 153
//   - trust_anchors: the same 28 IDs, but in one sorted order in all five
//     processes where 153 had a new order per process; see
//     chrome154TrustAnchors in extension_data.go
//   - ECH GREASE on AES-128-GCM only, payloads drawn from four sizes; no
//     server_padding
//   - HTTP/2 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p, HEADERS on
//     stream 1 with weight 256 exclusive, the transport default
//
// So Chrome_154 is the Chrome_152 spec with the sorted trust_anchors payload.
// The request headers real Chrome 154 sent, in order: sec-ch-ua
// "Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99" (the
// brand list and its GREASE entry are reshuffled every major version),
// sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests,
// user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user,
// sec-fetch-dest, accept-encoding "gzip, deflate, br, zstd", accept-language,
// priority "u=0, i".
var (
	Chrome_153 = func() ClientProfile {
		profile := Chrome_152
		profile.clientHelloId = derivedHelloID("Chrome", "153", Chrome_152.clientHelloId)

		return profile
	}()

	Chrome_153_PSK = func() ClientProfile {
		profile := Chrome_152_PSK
		profile.clientHelloId = derivedHelloID("Chrome", "153_PSK", Chrome_152_PSK.clientHelloId)

		return profile
	}()

	Chrome_154 = func() ClientProfile {
		profile := Chrome_152
		profile.clientHelloId = derivedHelloID("Chrome", "154", Chrome_152.clientHelloId, withSortedTrustAnchors)

		return profile
	}()

	Chrome_154_PSK = func() ClientProfile {
		profile := Chrome_152_PSK
		profile.clientHelloId = derivedHelloID("Chrome", "154_PSK", Chrome_152_PSK.clientHelloId, withSortedTrustAnchors)

		return profile
	}()
)

// withSortedTrustAnchors swaps the trust_anchors payload for Chrome 154's
// sorted one. It writes a new extension rather than editing the one in the
// spec, so the source profile's payload is never touched.
func withSortedTrustAnchors(spec *tls.ClientHelloSpec) {
	for i, extension := range spec.Extensions {
		if generic, ok := extension.(*tls.GenericExtension); ok && generic.Id == extensionTrustAnchorsID {
			spec.Extensions[i] = &tls.GenericExtension{Id: extensionTrustAnchorsID, Data: chrome154TrustAnchors}
		}
	}
}

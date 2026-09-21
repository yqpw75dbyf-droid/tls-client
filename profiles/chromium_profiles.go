package profiles

// Chromium_146 is Chromium 146 without Google's branding, which on the wire
// means Chrome 146 without the trust_anchors extension: the anchor IDs come
// from the Chrome Root Store, and a Chromium build that does not ship it does
// not advertise them. Edge shows the same absence for the same reason.
//
// Measured on 2026-09-21 against a real unbranded Chromium 146 build, the free
// CloakBrowser binary (a stealth Chromium fork whose TLS stack is stock
// BoringSSL), driven headless against tls.peet.ws/api/all twice:
//
//   - JA4 t13d1516h2_8daaf6152771_d8a2da3f94cd on both runs, JA3 differing
//     per run from the extension shuffle
//   - 16 extensions: the Chrome_146 set without trust_anchors (51764)
//   - the same cipher set as Chrome 146 (cipher hash 8daaf6152771), the eight
//     classic signature algorithms, X25519MLKEM768 first in the groups
//   - HTTP/2 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p, HEADERS on
//     stream 1 with weight 256 exclusive, and Chrome's header order
//
// That JA4 is also what Chrome_144 measures, because Chrome 144 predates the
// trust_anchors rollout: the two profiles are the same hello under different
// names. This one exists so that "unbranded Chromium 146" can be asked for by
// name with a Chrome/146 user agent, rather than by knowing that Chrome_144
// happens to coincide.
var Chromium_146 = func() ClientProfile {
	profile := Chrome_146
	profile.clientHelloId = helloIDWithoutExtension("Chromium", "146", Chrome_146.clientHelloId, extensionTrustAnchorsID)

	return profile
}()

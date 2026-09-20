package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/utls/dicttls"
)

// Tor Browser is Firefox ESR with the resumption trail stripped. Tor Browser
// 14.x sits on Firefox 128 ESR, and its handshake is Firefox's minus every
// artifact that could tie two connections together, plus the ESR feature set
// of its base rather than the rapid release one.
//
// The spec below is built from lexiforest/curl-impersonate's real Tor Browser
// 14.5 capture (tests/signatures/tor_14.5_macOS.yaml), extension for
// extension. Against the Firefox_135 profile in this package the differences
// are:
//
//   - no session_ticket (35) and no psk_key_exchange_modes (45): Tor disables
//     TLS session resumption so that connections cannot be correlated
//   - no SCT (18) and no compress_certificate (27)
//   - no X25519MLKEM768: Firefox 128 ESR predates the ML-KEM rollout, so the
//     groups start at X25519 and the key shares are X25519 and P-256
//   - 15 cipher suites rather than 17: the two ECDHE_ECDSA CBC suites are gone
//
// That leaves 13 extensions, which is itself the tell: a hello that looks
// like Firefox but carries no resumption machinery is how Tor Browser looks
// to every fingerprinting endpoint.
//
// The HTTP/2 half is Firefox's, with two fields the capture pins explicitly:
// the first request opens on stream 15, because Firefox numbers past the
// streams its old priority tree used to occupy, and the HEADERS frame carries
// weight 42, not exclusive, where the transport default would be Chrome's
// weight 256 exclusive.
//
// Usage. The handshake is the smaller half of looking like Tor Browser. The
// audit behind this profile found the flags come from everything around it,
// in this order:
//
//   - The IP. This fingerprint has no legitimate baseline anywhere but Tor
//     exit nodes. From a residential or datacenter address it is a
//     near-impossible combination and scores as automation before the
//     handshake is even weighed. Route it through the Tor daemon,
//     WithProxyUrl("socks5://127.0.0.1:9050"), or use a Firefox profile
//     instead: Tor Browser outside Tor is strictly worse than Firefox
//     outside Tor.
//   - The headers. With none set, the transport sends user-agent
//     Go-http-client/2.0 and accept-encoding "gzip, deflate, br". Tor
//     Browser 14.5 sends, in this order: user-agent, accept, accept-language,
//     accept-encoding, sec-gpc, upgrade-insecure-requests, sec-fetch-dest,
//     sec-fetch-mode, sec-fetch-site, sec-fetch-user, priority, te; with
//     accept-language "en-US,en;q=0.5", accept-encoding "gzip, deflate, br,
//     zstd", sec-gpc "1", priority "u=0, i" and te "trailers". Setting
//     accept-encoding yourself turns off the transport's automatic
//     decompression, so decode the body. The user agent is the Windows one
//     on every platform, "Mozilla/5.0 (Windows NT 10.0; rv:128.0)
//     Gecko/20100101 Firefox/128.0", because resistFingerprinting spoofs the
//     OS; the macOS string in the capture is from a test build with that
//     off. Never send sec-ch-ua: Firefox has no client hints.
//   - WithDisableHttp3 is not a workaround here, it is correct behavior: Tor
//     carries TCP only, so the real Tor Browser disables QUIC entirely and
//     never speaks HTTP/3.
//   - Do not combine with WithRandomTLSExtensionOrder: NSS never randomizes
//     extension order.
//
// Tor Browser 15.x, the current line, is Tor_15_0 below, captured from a
// real install. Tor Browser 13.x (Firefox 115 ESR) has no profile because no
// capture of it exists.
var Tor_14_5 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Tor",
		RandomExtensionOrder: false,
		Version:              "14.5",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					// The capture yaml records encrypted_client_hello as
					// "length: 0". That is the capture tool not decoding the
					// ECH body, not Tor sending an empty one: the same tool
					// records length 0 for Firefox 135, which certainly sends
					// a GREASE payload, and curl-impersonate builds both
					// targets with --ech. An empty ECH extension is malformed
					// (ECHClientHello needs at least its type byte) and
					// Cloudflare rejects it with "error decoding message",
					// measured. Tor Browser is Firefox here: GREASE ECH, same
					// candidate suites and payload sizes as Firefox_135.
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	streamID:       15,
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    41, // weight 42 on the wire, the byte is weight minus one
	},
}

// Tor_14_0 is the same Firefox 128 ESR base as 14.5; the 14.x line keeps one
// handshake.
var Tor_14_0 = func() ClientProfile {
	profile := Tor_14_5
	profile.clientHelloId = derivedHelloID("Tor", "14.0", Tor_14_5.clientHelloId)

	return profile
}()

// Tor_15_0 is Tor Browser 15, the current line, on Firefox 140 ESR. Captured
// from a real Tor Browser 15.0.20 (Firefox 140.14.0) on Windows, driven
// headless through Marionette over a live Tor circuit against
// tls.peet.ws/api/all on 2026-09-20:
//
//   - JA4 t13d1715h2_5b57614c22b0_a54fffd0eb61
//   - 17 cipher suites: Firefox's full list, the two ECDHE_ECDSA CBC suites
//     that 14.5 lacked are back
//   - 15 extensions in this order: server_name, extended_master_secret,
//     renegotiation_info, supported_groups, ec_point_formats, ALPN,
//     status_request, delegated_credentials, SCT, key_share,
//     supported_versions, signature_algorithms, record_size_limit,
//     compress_certificate (zlib, brotli, zstd), ECH GREASE (281 bytes)
//   - supported_groups opens with X25519MLKEM768 and the key share carries
//     it: the 140 ESR base is past the ML-KEM rollout
//   - still no session_ticket and no psk_key_exchange_modes: the Tor tell
//     survives the ESR bump
//   - HTTP/2 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s, no PRIORITY
//     frames, and the first request on stream 3 with weight 42 not
//     exclusive; Firefox never uses stream 1, and with the priority tree
//     gone nothing reserves 3 through 13 any more
//   - request headers, in order: user-agent "Mozilla/5.0 (Windows NT 10.0;
//     Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0", accept,
//     accept-language "en-US,en;q=0.5", accept-encoding "gzip, deflate,
//     br, zstd", sec-gpc "1", upgrade-insecure-requests, sec-fetch-dest,
//     sec-fetch-mode, sec-fetch-site, sec-fetch-user, priority "u=0, i",
//     te "trailers"
//
// Against Firefox_135 in this package the spec is the same extension list
// with session_ticket and psk_key_exchange_modes removed, which is how the
// 14.5 profile relates to Firefox 128 too. It is written out rather than
// derived so that the capture, not another profile, is its source.
var Tor_15_0 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Tor",
		RandomExtensionOrder: false,
		Version:              "15.0",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	streamID:       3,
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    41, // weight 42 on the wire, the byte is weight minus one
	},
}

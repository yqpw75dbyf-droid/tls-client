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
// Usage notes:
//
//   - Do not combine with WithRandomTLSExtensionOrder: NSS never randomizes
//     extension order.
//   - WithDisableHttp3 is not a workaround here, it is correct behavior: Tor
//     carries TCP only, so the real Tor Browser disables QUIC entirely and
//     never speaks HTTP/3.
//   - This fingerprint is expected to arrive from Tor exit nodes. Sites that
//     cross check the two will find a Tor Browser handshake from a
//     residential IP as odd as a Chrome handshake from an exit node.
//
// Tor Browser 13.x (Firefox 115 ESR) and 15.x (Firefox 140 ESR, current since
// October 2025) have no profile because no capture of them is published;
// curl-impersonate ships only the 14.5 one. Add them from captures when they
// exist, not from a guess.
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

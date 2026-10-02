package profiles

import (
	tls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/utls/dicttls"
)

// nssGREASEECH is the GREASE ECH extension Firefox and Tor Browser send, as
// NSS writes it in tls13_MaybeGreaseEch (lib/ssl/tls13ech.c, unchanged in this
// respect from NSS 3.77 in March 2022 through 2026):
//
//   - the KDF is always HKDF-SHA256
//   - the AEAD is AES-128-GCM or ChaCha20-Poly1305 on one random bit, and
//     never AES-256-GCM, which the profiles here used to offer a third of the
//     time
//   - the payload is not drawn at random. NSS encodes the inner ClientHello
//     the real hello would carry, pads the server name to 100 bytes, rounds
//     the total to 31 modulo 32, and adds the 16 byte tag, so one browser
//     build sends one size to every host with a name up to 100 bytes. The
//     profiles here used to alternate between two sizes, which no Firefox
//     does.
//
// innerLen is that padded inner length. It is 223 for every Firefox and Tor
// hello in this package except Firefox_148, whose two extra cipher suites
// push it to 255: 167 bytes, plus 2 per cipher suite, plus 2 per extension
// the inner hello compresses (all but server_name, supported_versions,
// encrypted_client_hello, padding and the TLS 1.2 only ones), rounded up to
// 31 modulo 32. That arithmetic was checked on a live Tor Browser 15.0.23
// against a local server: 219 bytes before padding, sizes stepping from 281
// to 313 at a 105 byte server name, exactly where it predicts.
//
// The ceilings: a server name over 100 bytes makes real NSS send a larger
// payload while this stays fixed, and a resumed connection from a _PSK
// profile carries the pre_shared_key inside the inner hello in real NSS.
// NSS bug 2060720 (August 2026) rounds to a multiple of 32 instead, which
// will move these sizes by one byte once a captured Firefox ships it; Tor
// Browser 16.0a13 on Firefox 153.4 ESR does not yet.
func nssGREASEECH(innerLen uint16) *tls.GREASEEncryptedClientHelloExtension {
	return &tls.GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
			{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
			{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
		},
		CandidatePayloadLens: []uint16{innerLen},
	}
}

// firefoxResumptionTrail inserts the two resumption extensions every real
// Firefox sends into a spec that is missing them: session_ticket right after
// ec_point_formats and psk_key_exchange_modes right after
// signature_algorithms, the positions the real captures show
// (lexiforest/curl-impersonate tests/signatures, Firefox 133 and 135).
//
// A Firefox hello without them is not vanilla Firefox at all: stripping
// exactly these is how Tor Browser looks, so a profile that loses them does
// not blend in, it stands out as the wrong browser.
func firefoxResumptionTrail(extensions []tls.TLSExtension) []tls.TLSExtension {
	patched := make([]tls.TLSExtension, 0, len(extensions)+2)

	for _, extension := range extensions {
		patched = append(patched, extension)

		switch extension.(type) {
		case *tls.SupportedPointsExtension:
			patched = append(patched, &tls.SessionTicketExtension{})
		case *tls.SignatureAlgorithmsExtension:
			patched = append(patched, &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
				tls.PskModeDHE,
			}})
		}
	}

	return patched
}

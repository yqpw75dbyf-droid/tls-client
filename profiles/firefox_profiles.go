package profiles

import (
	tls "github.com/bogdanfinn/utls"
)

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

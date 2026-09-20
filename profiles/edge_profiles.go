package profiles

import (
	tls "github.com/bogdanfinn/utls"
)

// Microsoft Edge is Chromium with Google's root store swapped for
// Microsoft's, and the handshake shows exactly one consequence of that: no
// trust_anchors extension, because the anchor IDs come from the Chrome Root
// Store. Everything else is Chrome's.
//
// Measured on this machine's Edge 153.0.4234.48 on Windows, driven headless
// against tls.peet.ws/api/all three times on 2026-09-20:
//
//   - JA4 t13d1516h2_8daaf6152771_806a8c22fdea on every run; JA3 differed
//     per run, as the extension shuffle makes it
//   - 16 extensions: the Chrome_152 set without trust_anchors (51764):
//     application_settings (17613, h2), status_request, ECH GREASE,
//     signature_algorithms, server_name, psk_key_exchange_modes,
//     ec_point_formats, supported_versions, session_ticket,
//     compress_certificate (brotli), extended_master_secret,
//     supported_groups, SCT, key_share, renegotiation_info, ALPN (h2,
//     http/1.1), between two GREASE extensions
//   - the same 16 cipher suites as Chrome 152 in the same order
//   - signature_algorithms opening with a GREASE value, then the ML-DSA
//     codepoints 0x0904, 0x0905, 0x0906, then the classic eight: Chrome
//     152's list, not Chrome 150's, even though the JA4 matches Chrome_150
//     because tls.peet.ws drops GREASE from the signature algorithms before
//     hashing
//   - key shares GREASE, X25519MLKEM768, X25519; no server_padding
//   - HTTP/2 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p, HEADERS
//     on stream 1 with weight 256 exclusive, the transport default
//
// So Edge_153 is the Chrome_152 spec with the trust_anchors extension
// removed, resolved at handshake time so the per connection GREASE signature
// algorithm keeps varying. The request headers real Edge 153 sent, for
// callers: sec-ch-ua "Microsoft Edge";v="153", "Not_A Brand";v="8",
// "Chromium";v="153", the rest in Chrome's order, and a user agent ending
// "Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0".

// helloIDWithoutExtension relabels a ClientHelloID and drops one generic
// extension from the spec it resolves to, pinning the spec to the source the
// way derivedHelloID does.
func helloIDWithoutExtension(client, version string, source tls.ClientHelloID, id uint16) tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               client,
		Version:              version,
		RandomExtensionOrder: source.RandomExtensionOrder,
		Seed:                 source.Seed,
		Weights:              source.Weights,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			spec, err := source.ToSpec()
			if err != nil {
				spec, err = tls.UTLSIdToSpec(source)
				if err != nil {
					return spec, err
				}
			}

			kept := make([]tls.TLSExtension, 0, len(spec.Extensions))

			for _, extension := range spec.Extensions {
				if generic, ok := extension.(*tls.GenericExtension); ok && generic.Id == id {
					continue
				}

				kept = append(kept, extension)
			}

			spec.Extensions = kept

			return spec, nil
		},
	}
}

const extensionTrustAnchorsID uint16 = 0xca34

var (
	Edge_153 = func() ClientProfile {
		profile := Chrome_152
		profile.clientHelloId = helloIDWithoutExtension("Edge", "153", Chrome_152.clientHelloId, extensionTrustAnchorsID)

		return profile
	}()

	Edge_153_PSK = func() ClientProfile {
		profile := Chrome_152_PSK
		profile.clientHelloId = helloIDWithoutExtension("Edge", "153_PSK", Chrome_152_PSK.clientHelloId, extensionTrustAnchorsID)

		return profile
	}()
)

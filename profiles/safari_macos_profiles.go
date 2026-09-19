package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

// Safari on macOS and Safari on iOS are the same Apple network stack, and the
// handshake shows it: the utls specs for iOS 15.5/15.6/iPad 15.6/16.0 and for
// Safari 15.6.1/16.0 on macOS are identical to the byte, only the case label
// differs. The iOS captures in this package are therefore the source for the
// macOS profiles below, the same way the Chrome captures were the source for
// the Opera ones.
//
// Unlike Opera, the two platforms did not always share the HTTP/2 half. The
// evidence, cross-checked against lexiforest/curl-impersonate's desktop
// captures (bin/curl_safari170, 180, 184, 260):
//
//	desktop 17.0  2:0;4:4194304;3:100          |10485760|m,s,p,a   window 4 MB
//	iOS     17.0  2:0;4:2097152;3:100          |10485760|m,s,p,a   window 2 MB
//	desktop 18.0  2:0;3:100;4:2097152;8:1;9:1  |10420225|m,s,a,p   == iOS 18.0
//	desktop 18.4  2:0;3:100;4:2097152;9:1      |10420225|m,s,a,p   == iOS 18.5
//	desktop 26.0  2:0;3:100;4:2097152;9:1      |10420225|m,s,a,p   == iOS 26.0
//
// Through Safari 17 the desktop kept a 4 MB initial window where iOS used
// 2 MB, the split already visible in the Safari_16_0 and Safari_IOS_16_0
// profiles. Safari 18 ended it: the desktop moved to the iOS block wholesale,
// window, order, connection flow and pseudo header order alike. So only
// Safari_17_0 overrides the HTTP/2 settings of its iOS base; 18.0, 18.5 and
// 26.0 carry them unchanged.
//
// The TLS milestones the captures encode, for picking a profile by target:
// 3DES and the CBC suites are still offered through 26.0, certificate
// compression is zlib rather than brotli, no session tickets are sent (so no
// resumption, matching curl-impersonate's --no-tls-session-ticket), and
// X25519MLKEM768 arrives at 26.0, not in 18.x.
//
// Do not combine these profiles with WithRandomTLSExtensionOrder. Safari has
// never randomized its extension order; a shuffled Safari hello is one no real
// Safari ever sent. The shuffle option belongs to Chromium shaped profiles,
// Chrome and Opera alike, where the real browser shuffles per connection.
//
// The point releases below each carry the handshake of their era's capture,
// because Apple changes the handshake per era, not per release. The eras and
// their evidence:
//
//	15.3 - 16.6   the 15.6.1 capture      curl-impersonate's desktop 15.3 and
//	                                      15.5 match it flag for flag, down to
//	                                      Apple's own duplicated
//	                                      rsa_pss_rsae_sha384 in the signature
//	                                      algorithms, and utls resolves 15.6.1
//	                                      and 16.0 from one shared spec
//	17.0 - 17.6   the 17.0 capture        ENABLE_PUSH=0 joins the SETTINGS
//	18.0 - 18.3   the 18.0 capture        settings 0x8 and 0x9 join, window
//	                                      drops to 2 MB, flow to 10420225,
//	                                      pseudo order becomes m,s,a,p; the
//	                                      real iOS 18.3 capture in
//	                                      lexiforest/curl_cffi issue 530 still
//	                                      shows this exact block
//	18.4 - 18.6   the 18.5 capture        setting 0x8 leaves, curl-impersonate's
//	                                      desktop 18.4 shows the same block
//	26.0 - 26.6   the 26.0 capture        X25519MLKEM768 joins the key shares;
//	                                      curl-impersonate ships one 26 target
//	                                      plus 26.0.1, seeing no change inside
//	                                      the line
//
// Safari 27 has no profile because as of September 2026 it has no capture:
// its release is imminent but not out. Add it from a capture when it ships,
// not from a guess.

// derivedHelloID relabels a ClientHelloID while pinning the spec to the source
// ID. Profiles that name a utls built in carry EmptyClientHelloSpecFactory and
// are resolved from the "Client-Version" string, so a bare rename would make
// that lookup miss and fail at handshake; resolving through the source first
// keeps both kinds of profile working.
func derivedHelloID(client, version string, source tls.ClientHelloID) tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               client,
		Version:              version,
		RandomExtensionOrder: source.RandomExtensionOrder,
		Seed:                 source.Seed,
		Weights:              source.Weights,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			if spec, err := source.ToSpec(); err == nil {
				return spec, nil
			}

			return tls.UTLSIdToSpec(source)
		},
	}
}

// macSafariProfile relabels an iOS Safari capture as the macOS Safari release
// on the same Apple stack, keeping the spec and, from Safari 18 on, the HTTP/2
// settings too.
func macSafariProfile(version string, iosBase ClientProfile) ClientProfile {
	profile := iosBase
	profile.clientHelloId = derivedHelloID("Safari", version, iosBase.clientHelloId)

	return profile
}

var (
	// Safari_17_0 gets a settings map of its own rather than a mutation of the
	// copied one, because the copy still shares the map with Safari_IOS_17_0.
	Safari_17_0 = func() ClientProfile {
		profile := macSafariProfile("17.0", Safari_IOS_17_0)
		profile.settings = map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingInitialWindowSize:    4194304,
			http2.SettingMaxConcurrentStreams: 100,
		}

		return profile
	}()

	Safari_18_0 = macSafariProfile("18.0", Safari_IOS_18_0)
	Safari_18_5 = macSafariProfile("18.5", Safari_IOS_18_5)
	Safari_26_0 = macSafariProfile("26.0", Safari_IOS_26_0)

	// The 15.3 - 16.6 era, on the 15.6.1 capture.
	Safari_15_3 = macSafariProfile("15.3", Safari_15_6_1)
	Safari_15_5 = macSafariProfile("15.5", Safari_15_6_1)
	Safari_16_1 = macSafariProfile("16.1", Safari_16_0)
	Safari_16_2 = macSafariProfile("16.2", Safari_16_0)
	Safari_16_3 = macSafariProfile("16.3", Safari_16_0)
	Safari_16_4 = macSafariProfile("16.4", Safari_16_0)
	Safari_16_5 = macSafariProfile("16.5", Safari_16_0)
	Safari_16_6 = macSafariProfile("16.6", Safari_16_0)

	// The 17.x era, on the 17.0 capture with its desktop 4 MB window.
	Safari_17_1 = macSafariProfile("17.1", Safari_17_0)
	Safari_17_2 = macSafariProfile("17.2", Safari_17_0)
	Safari_17_3 = macSafariProfile("17.3", Safari_17_0)
	Safari_17_4 = macSafariProfile("17.4", Safari_17_0)
	Safari_17_5 = macSafariProfile("17.5", Safari_17_0)
	Safari_17_6 = macSafariProfile("17.6", Safari_17_0)

	// 18.0 - 18.3 on the 18.0 capture, 18.4 and 18.6 on the 18.5 one.
	Safari_18_1 = macSafariProfile("18.1", Safari_18_0)
	Safari_18_2 = macSafariProfile("18.2", Safari_18_0)
	Safari_18_3 = macSafariProfile("18.3", Safari_18_0)
	Safari_18_4 = macSafariProfile("18.4", Safari_18_5)
	Safari_18_6 = macSafariProfile("18.6", Safari_18_5)

	// The 26.x era, on the 26.0 capture.
	Safari_26_1 = macSafariProfile("26.1", Safari_26_0)
	Safari_26_2 = macSafariProfile("26.2", Safari_26_0)
	Safari_26_3 = macSafariProfile("26.3", Safari_26_0)
	Safari_26_4 = macSafariProfile("26.4", Safari_26_0)
	Safari_26_5 = macSafariProfile("26.5", Safari_26_0)
	Safari_26_6 = macSafariProfile("26.6", Safari_26_0)
)

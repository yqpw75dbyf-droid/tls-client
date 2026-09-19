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
// Versions with no profile of their own sit between captures: 16.x behaves as
// 16.0, 17.x as 17.0, 18.1 through 18.6 as 18.0 or 18.5 whichever is nearer,
// 26.x as 26.0. Apple changes the handshake far less often than Chromium, so
// the point releases are much safer to approximate than the Chromium hole was.

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
)

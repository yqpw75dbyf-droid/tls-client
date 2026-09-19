package profiles

import (
	tls "github.com/bogdanfinn/utls"
)

// Opera ships the Chromium it is built on unchanged as far as the handshake is
// concerned: the same BoringSSL, the same network stack, so the same
// ClientHello and the same HTTP/2 SETTINGS. That is not a shortcut taken here
// for convenience, it is what the evidence says.
//
//   - utls' own HelloOpera_89/90/91 spec is identical on the wire to its
//     Chrome_102 and Chrome_103..109 specs. The two differ only in which alias
//     of a constant they spell: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 against
//     TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (both 0xcca8), and
//     CompressionNone against 0x00.
//   - The Opera_89/90/91 profiles below already carry the HTTP/2 settings of
//     Chrome_103..105, byte for byte, including connectionFlow 15663105.
//   - JA4 fingerprints observed in the wild put Opera 134 and Chrome 150/151 in
//     the same bucket, t13d1514h2_8daaf6152771_d85c08a3ce5e.
//
// Nothing in the handshake tells the two apart. What does tell them apart is
// the "OPR/<version>" token that Opera appends to the User-Agent, after
// Safari/537.36. That is a request header, so it belongs to the caller, not to
// a profile:
//
//	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
//	Gecko) Chrome/<chromium>.0.0.0 Safari/537.36 OPR/<opera>.0.0.0
//
// Each profile below therefore reuses the ClientHello spec and the HTTP/2
// settings of the Chrome profile for its Chromium base. The pairs come from
// Opera's release announcements. The offset is not constant: Opera skipped
// Chromium 129 and Chromium 136, so it drifts from +14 to +15 to +16.
//
//	Opera  Chromium  base            Opera  Chromium  base
//	  92     106     Chrome_106       115     130     Chrome_130_PSK
//	  93     107     Chrome_107       116     131     Chrome_131
//	  94     108     Chrome_108       117     132     Chrome_131      ~
//	  95     109     Chrome_109       118     133     Chrome_133
//	  96     110     Chrome_110       119     134     Chrome_133      ~
//	  97     111     Chrome_111       120     135     Chrome_133      ~
//	  98     112     Chrome_112       121     137     Chrome_133      ~
//	  99     113     Chrome_112  ~    122     138     Chrome_133      ~
//	 100     114     Chrome_112  ~    123     139     Chrome_144      ~
//	 101     115     Chrome_112  ~    124     140     Chrome_144      ~
//	 102     116     Chrome_112  ~    125     141     Chrome_144      ~
//	 103     117     Chrome_117       126     142     Chrome_144      ~
//	 104     118     Chrome_117  ~    127     143     Chrome_144      ~
//	 105     119     Chrome_117  ~    128     144     Chrome_144
//	 106     120     Chrome_120       129     145     Chrome_144      ~
//	 107     121     Chrome_120  ~    130     146     Chrome_146
//	 108     122     Chrome_120  ~    131     147     Chrome_146      ~
//	 109     123     Chrome_120  ~    132     148     Chrome_146      ~
//	 110     124     Chrome_124       133     149     Chrome_146      ~
//	 111     125     Chrome_124  ~    134     150     Chrome_150
//	 112     126     Chrome_124  ~    135     151     Chrome_150      ~
//	 113     127     Chrome_124  ~    136     152     Chrome_152
//	 114     128     Chrome_124  ~
//
// A "~" marks an Opera whose Chromium base has no profile of its own here, so
// the closest one by version distance stands in, which is sometimes the next
// one up rather than the one below. That is accurate whenever Chromium changed
// nothing in its ClientHello across the gap, and an approximation when it did.
//
// The one real hole is Chromium 134 to 143, which nothing here covers: this
// package jumps from Chrome_133 to Chrome_144, bogdanfinn/utls stops at
// HelloChrome_133 and so does refraction-networking/utls upstream. Opera 119
// to 127 sit in that hole and lean on whichever of Chrome_133 or Chrome_144 is
// nearer.
//
// Chromium did change its ClientHello inside that window, so those nine are
// approximations rather than matches. Measured JA4 for real Chrome, by
// extension count:
//
//	Chrome 134  t13d1513h2_8daaf6152771_6de1616fdcc3  13 extensions
//	Chrome 144  t13d1517h2_8daaf6152771_b6f405a00624  17 extensions
//	Chrome 149  t13d1516h2_8daaf6152771_d8a2da3f94cd  16 extensions
//
// Closing it needs captures, not cleverness: run a real Chromium 134 to 143 at
// a fingerprint endpoint and write the Chrome profiles from what it sends.
// Nothing Opera specific needs capturing, a Chrome profile for those releases
// fixes Opera for free. Guessing the spec instead would be worse than the gap,
// because a profile that claims a version it does not match is harder to catch
// than one that is openly approximate.
//
// Only the plain variants are defined. Say so if the PSK variants are wanted
// too; they would pair with the Chrome_*_PSK profiles the same way.

// operaProfile relabels a Chrome profile as the Opera release built on the same
// Chromium, keeping its ClientHello spec, its HTTP/2 settings and everything
// else the profile carries.
//
// The spec is resolved through the original ID rather than the new one on
// purpose. Profiles that name a utls built in, such as tls.HelloChrome_106,
// carry EmptyClientHelloSpecFactory and are resolved by utls from the
// "Chrome-106" string instead (u_parrots.go, applyPresetByID). Renaming the
// client to Opera would make that lookup miss and the handshake fail, so the
// spec is pinned to the source ID here and handed to utls ready made, which it
// prefers over the lookup anyway.
func operaProfile(operaVersion string, base ClientProfile) ClientProfile {
	source := base.clientHelloId

	profile := base
	profile.clientHelloId = tls.ClientHelloID{
		Client:               "Opera",
		Version:              operaVersion,
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

	return profile
}

var (
	Opera_92  = operaProfile("92", Chrome_106)
	Opera_93  = operaProfile("93", Chrome_107)
	Opera_94  = operaProfile("94", Chrome_108)
	Opera_95  = operaProfile("95", Chrome_109)
	Opera_96  = operaProfile("96", Chrome_110)
	Opera_97  = operaProfile("97", Chrome_111)
	Opera_98  = operaProfile("98", Chrome_112)
	Opera_99  = operaProfile("99", Chrome_112)
	Opera_100 = operaProfile("100", Chrome_112)
	Opera_101 = operaProfile("101", Chrome_112)
	Opera_102 = operaProfile("102", Chrome_112)
	Opera_103 = operaProfile("103", Chrome_117)
	Opera_104 = operaProfile("104", Chrome_117)
	Opera_105 = operaProfile("105", Chrome_117)
	Opera_106 = operaProfile("106", Chrome_120)
	Opera_107 = operaProfile("107", Chrome_120)
	Opera_108 = operaProfile("108", Chrome_120)
	Opera_109 = operaProfile("109", Chrome_120)
	Opera_110 = operaProfile("110", Chrome_124)
	Opera_111 = operaProfile("111", Chrome_124)
	Opera_112 = operaProfile("112", Chrome_124)
	Opera_113 = operaProfile("113", Chrome_124)
	Opera_114 = operaProfile("114", Chrome_124)
	Opera_115 = operaProfile("115", Chrome_130_PSK)
	Opera_116 = operaProfile("116", Chrome_131)
	Opera_117 = operaProfile("117", Chrome_131)
	Opera_118 = operaProfile("118", Chrome_133)
	Opera_119 = operaProfile("119", Chrome_133)
	Opera_120 = operaProfile("120", Chrome_133)
	Opera_121 = operaProfile("121", Chrome_133)
	Opera_122 = operaProfile("122", Chrome_133)
	Opera_123 = operaProfile("123", Chrome_144)
	Opera_124 = operaProfile("124", Chrome_144)
	Opera_125 = operaProfile("125", Chrome_144)
	Opera_126 = operaProfile("126", Chrome_144)
	Opera_127 = operaProfile("127", Chrome_144)
	Opera_128 = operaProfile("128", Chrome_144)
	Opera_129 = operaProfile("129", Chrome_144)
	Opera_130 = operaProfile("130", Chrome_146)
	Opera_131 = operaProfile("131", Chrome_146)
	Opera_132 = operaProfile("132", Chrome_146)
	Opera_133 = operaProfile("133", Chrome_146)
	Opera_134 = operaProfile("134", Chrome_150)
	Opera_135 = operaProfile("135", Chrome_150)
	Opera_136 = operaProfile("136", Chrome_152)
)

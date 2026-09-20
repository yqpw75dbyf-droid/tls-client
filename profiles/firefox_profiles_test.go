package profiles

import (
	"strings"
	"testing"

	tls "github.com/bogdanfinn/utls"
)

// TestFirefoxProfilesCarryTheResumptionTrail checks every plain Firefox
// profile for the two extensions all real Firefox hellos carry,
// session_ticket and psk_key_exchange_modes. Losing exactly these two is Tor
// Browser's signature, so a Firefox profile without them impersonates the
// wrong browser. The PSK variants model a resumed hello and are exempt.
func TestFirefoxProfilesCarryTheResumptionTrail(t *testing.T) {
	for name, profile := range MappedTLSClients {
		if !strings.HasPrefix(name, "firefox_") || strings.HasSuffix(name, "_PSK") {
			continue
		}

		spec, err := resolveSpec(profile.clientHelloId)
		if err != nil {
			continue // TestMappedProfilesResolveToASpec reports these
		}

		var ticket, pskModes bool

		for _, extension := range spec.Extensions {
			switch extension.(type) {
			case *tls.SessionTicketExtension:
				ticket = true
			case *tls.PSKKeyExchangeModesExtension:
				pskModes = true
			}
		}

		if !ticket {
			t.Errorf("%s sends no session_ticket: that is Tor's tell, not Firefox's", name)
		}

		if !pskModes {
			t.Errorf("%s sends no psk_key_exchange_modes", name)
		}
	}
}

// TestModernFirefoxHTTP2 pins the HTTP/2 half of the tree-less Firefox
// profiles to the real captures: the first request opens on stream 15 and
// HEADERS carries weight 42 not exclusive, never the transport's Chrome
// default. The older profiles reach stream 15 through their PRIORITY tree,
// whose last frame sets the next stream to 15, so they need no streamID.
func TestModernFirefoxHTTP2(t *testing.T) {
	for _, x := range []struct {
		name    string
		profile ClientProfile
	}{
		{"firefox_132", Firefox_132},
		{"firefox_133", Firefox_133},
		{"firefox_135", Firefox_135},
		{"firefox_146_PSK", Firefox_146_PSK},
		{"firefox_147", Firefox_147},
		{"firefox_147_PSK", Firefox_147_PSK},
		{"firefox_148", Firefox_148},
	} {
		if x.profile.streamID != 15 {
			t.Errorf("%s opens on stream %d, Firefox opens on 15", x.name, x.profile.streamID)
		}

		hp := x.profile.headerPriority
		if hp == nil {
			t.Errorf("%s has no headerPriority: the transport would fall back to Chrome's weight 256 exclusive", x.name)
			continue
		}

		if hp.Exclusive || hp.StreamDep != 0 || hp.Weight != 41 {
			t.Errorf("%s headerPriority = %+v, want weight 41 (42 on the wire), not exclusive, dep 0", x.name, *hp)
		}
	}
}

// TestFirefoxExtensionCountsMatchTheCaptures pins the repaired specs to the
// real capture totals: Firefox 133 sends 16 extensions, 135 sends 17 (SCT
// arrived in between), and the repaired 110 matches its own era's 15.
func TestFirefoxExtensionCountsMatchTheCaptures(t *testing.T) {
	for _, x := range []struct {
		name string
		p    ClientProfile
		want int
	}{
		{"firefox_110", Firefox_110, 15},
		{"firefox_120", Firefox_120, 15},
		{"firefox_132", Firefox_132, 16},
		{"firefox_133", Firefox_133, 16},
		{"firefox_135", Firefox_135, 17},
	} {
		spec, err := resolveSpec(x.p.clientHelloId)
		if err != nil {
			t.Fatalf("%s: %v", x.name, err)
		}

		if len(spec.Extensions) != x.want {
			t.Errorf("%s has %d extensions, capture says %d", x.name, len(spec.Extensions), x.want)
		}
	}
}

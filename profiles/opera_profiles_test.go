package profiles

import (
	"fmt"
	"slices"
	"testing"

	tls "github.com/bogdanfinn/utls"
)

// resolveSpec mirrors how utls picks a spec in applyPresetByID: the factory
// first, the "Client-Version" lookup only if the factory returns an error.
func resolveSpec(id tls.ClientHelloID) (tls.ClientHelloSpec, error) {
	if spec, err := id.ToSpec(); err == nil {
		return spec, nil
	}

	return tls.UTLSIdToSpec(id)
}

func extensionTypes(spec tls.ClientHelloSpec) []string {
	types := make([]string, len(spec.Extensions))

	for i, extension := range spec.Extensions {
		types[i] = fmt.Sprintf("%T", extension)
	}

	return types
}

// TestMappedProfilesResolveToASpec guards the whole registry, not just Opera. A
// profile that names a client utls cannot resolve builds fine and only fails at
// handshake time, on the first request, which is far from the edit that caused
// it.
func TestMappedProfilesResolveToASpec(t *testing.T) {
	for name, profile := range MappedTLSClients {
		spec, err := resolveSpec(profile.clientHelloId)
		if err != nil {
			t.Errorf("%s (%s): no spec: %v", name, profile.clientHelloId.Str(), err)
			continue
		}

		if len(spec.CipherSuites) == 0 {
			t.Errorf("%s: spec has no cipher suites", name)
		}

		if len(spec.Extensions) == 0 {
			t.Errorf("%s: spec has no extensions", name)
		}
	}
}

// TestOperaProfilesMatchTheirChromiumBase is the check on operaProfile. Opera
// is Chrome relabelled, so the relabelling must not move a byte of the
// handshake.
//
// The failure it exists to catch is specific: a profile that names a utls built
// in, such as tls.HelloChrome_106, carries EmptyClientHelloSpecFactory and is
// resolved from the string "Chrome-106". Rename the client to Opera without
// pinning the spec to the original ID and that lookup misses, so every request
// on the profile fails at handshake.
func TestOperaProfilesMatchTheirChromiumBase(t *testing.T) {
	pairs := []struct {
		name   string
		opera  ClientProfile
		chrome ClientProfile
	}{
		// Chrome_106 through Chrome_112 name utls built ins, so these are the
		// cases where a broken relabelling would lose the spec entirely.
		{"opera_92 on chrome_106", Opera_92, Chrome_106},
		{"opera_98 on chrome_112", Opera_98, Chrome_112},
		// The rest carry their own SpecFactory.
		{"opera_103 on chrome_117", Opera_103, Chrome_117},
		{"opera_110 on chrome_124", Opera_110, Chrome_124},
		// Opera 105 (Chromium 119) leans up to Chrome_120 for its GREASE ECH,
		// and Opera 115 (Chromium 130) leans down to Chrome_124 for its Kyber
		// key share; the version exact Chrome_130_PSK carries no PQ share.
		{"opera_105 on chrome_120", Opera_105, Chrome_120},
		{"opera_115 on chrome_124", Opera_115, Chrome_124},
		// Opera 121 and 127 straddle the Chromium 134 to 143 hole: 121 is on
		// Chromium 137 and leans down to Chrome_133, 127 is on Chromium 143 and
		// leans up to Chrome_144. They must not share a base.
		{"opera_121 on chrome_133", Opera_121, Chrome_133},
		{"opera_127 on chrome_144", Opera_127, Chrome_144},
		{"opera_128 on chrome_144", Opera_128, Chrome_144},
		{"opera_136 on chrome_152", Opera_136, Chrome_152},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			// An Opera profile must always resolve through its own factory.
			// Falling through to the lookup means the spec was not pinned.
			operaSpec, err := pair.opera.clientHelloId.ToSpec()
			if err != nil {
				t.Fatalf("spec factory failed, the lookup would be tried next and miss: %v", err)
			}

			chromeSpec, err := resolveSpec(pair.chrome.clientHelloId)
			if err != nil {
				t.Fatalf("no spec for the chromium base: %v", err)
			}

			if !slices.Equal(operaSpec.CipherSuites, chromeSpec.CipherSuites) {
				t.Errorf("cipher suites differ from the chromium base:\n opera:  %v\n chrome: %v",
					operaSpec.CipherSuites, chromeSpec.CipherSuites)
			}

			if !slices.Equal(extensionTypes(operaSpec), extensionTypes(chromeSpec)) {
				t.Errorf("extensions differ from the chromium base:\n opera:  %v\n chrome: %v",
					extensionTypes(operaSpec), extensionTypes(chromeSpec))
			}

			// The HTTP/2 half of the fingerprint travels with the profile, so
			// it has to survive the relabelling too.
			if !slices.Equal(pair.opera.settingsOrder, pair.chrome.settingsOrder) {
				t.Errorf("h2 settings order differs: %v vs %v", pair.opera.settingsOrder, pair.chrome.settingsOrder)
			}

			if pair.opera.connectionFlow != pair.chrome.connectionFlow {
				t.Errorf("connection flow differs: %d vs %d", pair.opera.connectionFlow, pair.chrome.connectionFlow)
			}
		})
	}
}

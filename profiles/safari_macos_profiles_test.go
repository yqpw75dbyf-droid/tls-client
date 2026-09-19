package profiles

import (
	"slices"
	"testing"

	"github.com/bogdanfinn/fhttp/http2"
)

// TestMacSafariProfilesMatchTheirIOSBase checks that relabelling an iOS
// capture as macOS Safari moves no byte of the ClientHello, and that every
// macOS profile resolves through its own factory rather than the
// "Client-Version" lookup, which knows no "Safari-18.0".
func TestMacSafariProfilesMatchTheirIOSBase(t *testing.T) {
	pairs := []struct {
		name   string
		mac    ClientProfile
		source ClientProfile
	}{
		{"safari_17_0 on ios_17_0", Safari_17_0, Safari_IOS_17_0},
		{"safari_18_0 on ios_18_0", Safari_18_0, Safari_IOS_18_0},
		{"safari_18_5 on ios_18_5", Safari_18_5, Safari_IOS_18_5},
		{"safari_26_0 on ios_26_0", Safari_26_0, Safari_IOS_26_0},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			macSpec, err := pair.mac.clientHelloId.ToSpec()
			if err != nil {
				t.Fatalf("spec factory failed, the lookup would be tried next and miss: %v", err)
			}

			sourceSpec, err := resolveSpec(pair.source.clientHelloId)
			if err != nil {
				t.Fatalf("no spec for the iOS source: %v", err)
			}

			if !slices.Equal(macSpec.CipherSuites, sourceSpec.CipherSuites) {
				t.Errorf("cipher suites differ from the iOS source:\n mac: %v\n ios: %v",
					macSpec.CipherSuites, sourceSpec.CipherSuites)
			}

			if !slices.Equal(extensionTypes(macSpec), extensionTypes(sourceSpec)) {
				t.Errorf("extensions differ from the iOS source:\n mac: %v\n ios: %v",
					extensionTypes(macSpec), extensionTypes(sourceSpec))
			}
		})
	}
}

// TestMacSafariEraAliases checks that every point release resolves to exactly
// its era's handshake: same cipher suites, same extension sequence, same
// HTTP/2 settings values, and a version string of its own.
func TestMacSafariEraAliases(t *testing.T) {
	eras := []struct {
		base    ClientProfile
		aliases map[string]ClientProfile
	}{
		{Safari_15_6_1, map[string]ClientProfile{
			"15.3": Safari_15_3, "15.5": Safari_15_5,
		}},
		{Safari_16_0, map[string]ClientProfile{
			"16.1": Safari_16_1, "16.2": Safari_16_2, "16.3": Safari_16_3,
			"16.4": Safari_16_4, "16.5": Safari_16_5, "16.6": Safari_16_6,
		}},
		{Safari_17_0, map[string]ClientProfile{
			"17.1": Safari_17_1, "17.2": Safari_17_2, "17.3": Safari_17_3,
			"17.4": Safari_17_4, "17.5": Safari_17_5, "17.6": Safari_17_6,
		}},
		{Safari_18_0, map[string]ClientProfile{
			"18.1": Safari_18_1, "18.2": Safari_18_2, "18.3": Safari_18_3,
		}},
		{Safari_18_5, map[string]ClientProfile{
			"18.4": Safari_18_4, "18.6": Safari_18_6,
		}},
		{Safari_26_0, map[string]ClientProfile{
			"26.1": Safari_26_1, "26.2": Safari_26_2, "26.3": Safari_26_3,
			"26.4": Safari_26_4, "26.5": Safari_26_5, "26.6": Safari_26_6,
		}},
	}

	for _, era := range eras {
		baseSpec, err := resolveSpec(era.base.clientHelloId)
		if err != nil {
			t.Fatalf("no spec for era base %s: %v", era.base.clientHelloId.Str(), err)
		}

		for version, alias := range era.aliases {
			aliasSpec, err := alias.clientHelloId.ToSpec()
			if err != nil {
				t.Errorf("safari %s: spec factory failed: %v", version, err)
				continue
			}

			if alias.clientHelloId.Version != version {
				t.Errorf("safari %s: version string is %q", version, alias.clientHelloId.Version)
			}

			if !slices.Equal(aliasSpec.CipherSuites, baseSpec.CipherSuites) {
				t.Errorf("safari %s: cipher suites differ from era base", version)
			}

			if !slices.Equal(extensionTypes(aliasSpec), extensionTypes(baseSpec)) {
				t.Errorf("safari %s: extensions differ from era base", version)
			}

			for id, want := range era.base.settings {
				if got := alias.settings[id]; got != want {
					t.Errorf("safari %s: setting %v = %d, era base sends %d", version, id, got, want)
				}
			}

			if alias.connectionFlow != era.base.connectionFlow {
				t.Errorf("safari %s: connection flow %d, era base %d", version, alias.connectionFlow, era.base.connectionFlow)
			}
		}
	}
}

// TestMacSafariHTTP2Blocks pins the desktop HTTP/2 fingerprints to what
// lexiforest/curl-impersonate's desktop captures show: Safari 17 keeps the
// 4 MB window that iOS never had, Safari 18 on shares the iOS block entirely.
func TestMacSafariHTTP2Blocks(t *testing.T) {
	// The 17.0 override must not leak into the iOS profile it was copied
	// from: the copy shares the settings map unless a fresh one is built.
	if got := Safari_IOS_17_0.settings[http2.SettingInitialWindowSize]; got != 2097152 {
		t.Fatalf("Safari_IOS_17_0 window changed to %d: the macOS override mutated the shared map", got)
	}

	if got := Safari_17_0.settings[http2.SettingInitialWindowSize]; got != 4194304 {
		t.Errorf("Safari_17_0 window = %d, desktop Safari 17 sends 4194304", got)
	}

	if got := Safari_17_0.connectionFlow; got != 10485760 {
		t.Errorf("Safari_17_0 connection flow = %d, want 10485760", got)
	}

	if want := []string{":method", ":scheme", ":path", ":authority"}; !slices.Equal(Safari_17_0.pseudoHeaderOrder, want) {
		t.Errorf("Safari_17_0 pseudo order = %v, want %v", Safari_17_0.pseudoHeaderOrder, want)
	}

	for _, p := range []struct {
		name    string
		profile ClientProfile
	}{
		{"Safari_18_0", Safari_18_0},
		{"Safari_18_5", Safari_18_5},
		{"Safari_26_0", Safari_26_0},
	} {
		if got := p.profile.settings[http2.SettingInitialWindowSize]; got != 2097152 {
			t.Errorf("%s window = %d, want 2097152: desktop joined the iOS block at 18", p.name, got)
		}

		if got := p.profile.connectionFlow; got != 10420225 {
			t.Errorf("%s connection flow = %d, want 10420225", p.name, got)
		}

		if want := []string{":method", ":scheme", ":authority", ":path"}; !slices.Equal(p.profile.pseudoHeaderOrder, want) {
			t.Errorf("%s pseudo order = %v, want %v", p.name, p.profile.pseudoHeaderOrder, want)
		}
	}

	// 18.0 sent both 0x8 and 0x9, 18.5 and 26.0 dropped 0x8.
	if _, ok := Safari_18_0.settings[http2.SettingID(0x8)]; !ok {
		t.Error("Safari_18_0 lost setting 0x8")
	}

	for _, p := range []struct {
		name    string
		profile ClientProfile
	}{
		{"Safari_18_5", Safari_18_5},
		{"Safari_26_0", Safari_26_0},
	} {
		if _, ok := p.profile.settings[http2.SettingID(0x8)]; ok {
			t.Errorf("%s carries setting 0x8, which only 18.0 sent", p.name)
		}

		if _, ok := p.profile.settings[http2.SettingID(0x9)]; !ok {
			t.Errorf("%s lost setting 0x9", p.name)
		}
	}
}

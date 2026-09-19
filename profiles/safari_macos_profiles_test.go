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

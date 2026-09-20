package profiles

import (
	"slices"
	"testing"
)

// chrome153TrustAnchorsCapture is the trust_anchors payload branded Chrome
// 153.0.8010.48 sent on 2026-09-20, kept here as the evidence for
// Chrome_153 reusing the Chrome 152 anchors: the same IDs in a different
// per process order. It is test data, not a runtime constant, because the
// runtime already carries the same set.
const chrome153TrustAnchorsCapture = "00b804d679090404d679090f0582df13020108839a648c9b2d010b08839a648c9b2d010d0582df1302120582df13020f0582df13021408839a648c9b2d010c04d679090808839a648c9b2d010a08839a648c9b2d010908839a648c9b2d010704d679090b08839a648c9b2d01130582df13021308839a648c9b2d010804d679090d04d679090104d679090c04d679090708839a648c9b2d011204d679090a04d67909050582df1302060582df13020d04d67909060582df13020e"

func TestChrome153IsChrome152OnTheWire(t *testing.T) {
	for _, pair := range []struct {
		name string
		new  ClientProfile
		base ClientProfile
	}{
		{"chrome_153 on chrome_152", Chrome_153, Chrome_152},
		{"chrome_153_PSK on chrome_152_PSK", Chrome_153_PSK, Chrome_152_PSK},
	} {
		t.Run(pair.name, func(t *testing.T) {
			newSpec, err := pair.new.clientHelloId.ToSpec()
			if err != nil {
				t.Fatalf("spec factory failed: %v", err)
			}

			baseSpec, err := resolveSpec(pair.base.clientHelloId)
			if err != nil {
				t.Fatalf("no spec for the base: %v", err)
			}

			if !slices.Equal(newSpec.CipherSuites, baseSpec.CipherSuites) {
				t.Error("cipher suites differ from the 152 base")
			}

			if !slices.Equal(extensionTypes(newSpec), extensionTypes(baseSpec)) {
				t.Error("extensions differ from the 152 base")
			}

			if !slices.Equal(pair.new.settingsOrder, pair.base.settingsOrder) || pair.new.connectionFlow != pair.base.connectionFlow {
				t.Error("HTTP/2 half differs from the 152 base")
			}
		})
	}
}

// TestChrome153TrustAnchorsMatchThe152Capture pins the reuse of the 152
// anchors to the real 153 capture: same 28 IDs, order aside.
func TestChrome153TrustAnchorsMatchThe152Capture(t *testing.T) {
	ids := func(capture string) []string {
		records, err := splitTrustAnchors(capture)
		if err != nil {
			t.Fatalf("bad capture: %v", err)
		}

		out := make([]string, 0, len(records))
		for _, record := range records {
			out = append(out, string(record))
		}

		slices.Sort(out)

		return out
	}

	got, want := ids(chrome153TrustAnchorsCapture), ids(chrome152TrustAnchorsCapture)
	if len(got) != 28 || !slices.Equal(got, want) {
		t.Errorf("Chrome 153 sent %d anchor IDs and 152 sent %d; the sets differ, so Chrome_153 must carry its own payload", len(got), len(want))
	}
}

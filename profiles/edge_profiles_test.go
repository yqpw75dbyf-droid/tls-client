package profiles

import (
	"slices"
	"testing"

	tls "github.com/bogdanfinn/utls"
)

// TestEdge153IsChrome152WithoutTrustAnchors pins Edge_153 to the real Edge
// 153 capture: Chrome 152's hello with the trust_anchors extension gone and
// nothing else changed, GREASE signature algorithm included.
func TestEdge153IsChrome152WithoutTrustAnchors(t *testing.T) {
	for _, pair := range []struct {
		name string
		edge ClientProfile
		base ClientProfile
	}{
		{"edge_153 on chrome_152", Edge_153, Chrome_152},
		{"edge_153_PSK on chrome_152_PSK", Edge_153_PSK, Chrome_152_PSK},
	} {
		t.Run(pair.name, func(t *testing.T) {
			edgeSpec, err := pair.edge.clientHelloId.ToSpec()
			if err != nil {
				t.Fatalf("spec factory failed: %v", err)
			}

			baseSpec, err := resolveSpec(pair.base.clientHelloId)
			if err != nil {
				t.Fatalf("no spec for the base: %v", err)
			}

			if !slices.Equal(edgeSpec.CipherSuites, baseSpec.CipherSuites) {
				t.Error("cipher suites differ from Chrome 152")
			}

			if len(edgeSpec.Extensions) != len(baseSpec.Extensions)-1 {
				t.Errorf("%d extensions, want Chrome 152's %d minus one", len(edgeSpec.Extensions), len(baseSpec.Extensions))
			}

			var grease bool

			for _, extension := range edgeSpec.Extensions {
				switch v := extension.(type) {
				case *tls.GenericExtension:
					if v.Id == extensionTrustAnchorsID {
						t.Error("still carries trust_anchors: Edge uses Microsoft's root program and never sends it")
					}
				case *tls.SignatureAlgorithmsExtension:
					first := uint16(v.SupportedSignatureAlgorithms[0])
					grease = first&0x0f0f == 0x0a0a && first>>8 == first&0xff
				}
			}

			if !grease {
				t.Error("signature algorithms do not open with a GREASE value: Edge 153 sends Chrome 152's list, not Chrome 150's")
			}

			if !slices.Equal(pair.edge.settingsOrder, pair.base.settingsOrder) || pair.edge.connectionFlow != pair.base.connectionFlow {
				t.Error("HTTP/2 half differs from Chrome 152")
			}
		})
	}
}

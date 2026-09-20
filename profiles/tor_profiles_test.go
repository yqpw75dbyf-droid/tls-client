package profiles

import (
	"slices"
	"testing"

	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

// TestTorSpecMatchesTheCapture pins Tor_14_5 to the real Tor Browser 14.5
// capture in lexiforest/curl-impersonate (tests/signatures/tor_14.5_macOS.yaml).
func TestTorSpecMatchesTheCapture(t *testing.T) {
	spec, err := Tor_14_5.clientHelloId.ToSpec()
	if err != nil {
		t.Fatalf("no spec: %v", err)
	}

	wantCiphers := []uint16{
		4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200,
		49171, 49172, 156, 157, 47, 53,
	}
	if !slices.Equal(spec.CipherSuites, wantCiphers) {
		t.Errorf("cipher suites = %v, capture says %v", spec.CipherSuites, wantCiphers)
	}

	if len(spec.Extensions) != 13 {
		t.Errorf("%d extensions, the capture has exactly 13", len(spec.Extensions))
	}

	// The whole point of the profile: no resumption trail, no SCT, no cert
	// compression, no post quantum share on the 128 ESR base. ECH stays the
	// Firefox GREASE extension: the capture's "length: 0" for it is the
	// capture tool not decoding the body (it says the same for Firefox 135),
	// and an actually empty ECH extension is malformed and gets the
	// handshake rejected by Cloudflare. Guard against that "fix" returning.
	var greaseECH bool

	for _, extension := range spec.Extensions {
		switch v := extension.(type) {
		case *tls.GREASEEncryptedClientHelloExtension:
			greaseECH = true
		case *tls.GenericExtension:
			if v.Id == 0xfe0d {
				t.Error("ECH is a bare extension: an empty ECH body is malformed and Cloudflare rejects the handshake")
			}
		case *tls.SessionTicketExtension:
			t.Error("carries session_ticket: Tor strips it, that is its tell")
		case *tls.PSKKeyExchangeModesExtension:
			t.Error("carries psk_key_exchange_modes: Tor strips it")
		case *tls.SCTExtension:
			t.Error("carries SCT: the capture has none")
		case *tls.UtlsCompressCertExtension:
			t.Error("carries compress_certificate: the capture has none")
		case *tls.KeyShareExtension:
			var groups []tls.CurveID
			for _, share := range v.KeyShares {
				groups = append(groups, share.Group)
			}
			if !slices.Equal(groups, []tls.CurveID{tls.X25519, tls.CurveP256}) {
				t.Errorf("key shares = %v, capture says X25519 and P-256 only", groups)
			}
		}
	}

	if !greaseECH {
		t.Error("no GREASE ECH extension: Tor Browser sends Firefox's")
	}

	// The HTTP/2 half: Firefox block, first stream 15, weight 42 on the wire
	// and never the transport's Chrome shaped default.
	if Tor_14_5.connectionFlow != 12517377 {
		t.Errorf("connection flow = %d, want 12517377", Tor_14_5.connectionFlow)
	}

	if Tor_14_5.streamID != 15 {
		t.Errorf("first stream = %d, Firefox lineage opens on 15", Tor_14_5.streamID)
	}

	if want := []string{":method", ":path", ":authority", ":scheme"}; !slices.Equal(Tor_14_5.pseudoHeaderOrder, want) {
		t.Errorf("pseudo order = %v, want %v", Tor_14_5.pseudoHeaderOrder, want)
	}

	hp := Tor_14_5.headerPriority
	if hp == nil || hp.Exclusive || hp.StreamDep != 0 || hp.Weight != 41 {
		t.Errorf("headerPriority = %+v, want weight 41 (42 on the wire), not exclusive, dep 0", hp)
	}

	if got := Tor_14_5.settings[http2.SettingInitialWindowSize]; got != 131072 {
		t.Errorf("initial window = %d, want 131072", got)
	}
}

// TestTor14AliasMatches keeps 14.0 on the same handshake as 14.5.
func TestTor14AliasMatches(t *testing.T) {
	aliasSpec, err := Tor_14_0.clientHelloId.ToSpec()
	if err != nil {
		t.Fatalf("spec factory failed: %v", err)
	}

	baseSpec, _ := Tor_14_5.clientHelloId.ToSpec()

	if !slices.Equal(aliasSpec.CipherSuites, baseSpec.CipherSuites) {
		t.Error("cipher suites differ between 14.0 and 14.5")
	}

	if !slices.Equal(extensionTypes(aliasSpec), extensionTypes(baseSpec)) {
		t.Error("extensions differ between 14.0 and 14.5")
	}

	if Tor_14_0.streamID != 15 || Tor_14_0.headerPriority == nil {
		t.Error("14.0 lost the HTTP/2 half of the profile")
	}
}

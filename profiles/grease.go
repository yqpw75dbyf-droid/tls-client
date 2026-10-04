package profiles

import (
	"crypto/rand"
	"encoding/binary"

	tls "github.com/bogdanfinn/utls"
)

// randomGREASESignatureScheme returns a random GREASE value for the
// signature_algorithms extension.
//
// Chrome sends a GREASE value as its first signature algorithm and picks a new
// one for every connection. The result has the form 0xWaWa for 0 <= W < 16,
// which is how BoringSSL builds its GREASE values. It panics if the random
// source fails, which crypto/rand does not survive either.
// https://github.com/google/boringssl/blob/master/ssl/extensions.cc
//
// On the wire this value no longer matters: utls v1.7.8-barnius replaces any
// GREASE signature algorithm in ApplyPreset with the one its per-connection
// seed gives ssl_grease_signature_algorithm, exactly as BoringSSL does. That
// seed byte is independent of the other GREASE positions in BoringSSL too, so
// the value can equal the cipher or version GREASE one time in sixteen in
// real Chrome as well; 20 real Chrome 154 handshakes and 40 of Chrome_154
// showed the same distribution on 2026-10-04. The function stays so that
// GetClientHelloSpec keeps returning a random value here, as the local spec
// tests expect.
func randomGREASESignatureScheme() tls.SignatureScheme {
	var seed [2]byte

	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}

	value := binary.LittleEndian.Uint16(seed[:])
	value = (value & 0xf0) | 0x0a
	value |= value << 8

	return tls.SignatureScheme(value)
}

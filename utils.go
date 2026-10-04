package tls_client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
)

func Int64ToInt(x int64) (int, error) {
	if x < math.MinInt || x > math.MaxInt {
		return 0, fmt.Errorf("int64 value %d out of int range [%d, %d]", x, math.MinInt, math.MaxInt)
	}
	return int(x), nil
}

// generateGREASESettingID returns a reserved HTTP/3 setting identifier drawn
// the way Chrome's QUIC stack draws it (quiche,
// QuicSendControlStream::MaybeSendSettingsFrame): 0x1f * N + 0x21 with N a
// random 32-bit value. N used to come from [1e9, 1e10), which put 63% of the
// identifiers above the largest one Chrome can send (0x1f * (2^32-1) + 0x21)
// and never produced the 23% Chrome sends below 1e9.
func generateGREASESettingID() uint64 {
	var buf [4]byte
	rand.Read(buf[:])

	return 0x1f*uint64(binary.BigEndian.Uint32(buf[:])) + 0x21
}

// generateGREASESettingValue generates a random non-zero 32-bit value for GREASE
func generateGREASESettingValue() uint64 {
	var buf [4]byte
	rand.Read(buf[:])
	val := binary.BigEndian.Uint32(buf[:])
	// Chrome never sends 0
	if val == 0 {
		val = 1
	}
	return uint64(val)
}

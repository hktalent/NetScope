//go:build linux

package capture

import (
	"encoding/hex"
	"os"
	"strings"
)

func defaultIfaceOS() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		// Destination 00000000 = default route
		if f[1] == "00000000" {
			_ = hex.DecodedLen
			return f[0]
		}
	}
	return ""
}

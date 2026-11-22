//go:build linux

package proc

import (
	"fmt"
	"os"
)

// resolvePath 读 /proc/<pid>/exe 符号链接
func resolvePath(pid int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

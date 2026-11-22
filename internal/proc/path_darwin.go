//go:build darwin

package proc

/*
#include <libproc.h>
#include <sys/proc_info.h>
*/
import "C"

import "unsafe"

const pidPathMax = 4096 // PROC_PIDPATHINFO_MAXSIZE

// resolvePath 用 libproc 拿进程可执行文件绝对路径（比 ps 解析更准）
func resolvePath(pid int) string {
	buf := make([]byte, pidPathMax)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

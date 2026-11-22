package httpurl

import (
	"bytes"
	"strings"
)

var methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

// ParseRequest 从一个 TCP payload 中解析首个 HTTP/1.x 请求
// 返回 host（来自 Host 头，可能为空）与完整 URL
func ParseRequest(payload []byte) (host, url string, ok bool) {
	head := payload
	if i := bytes.Index(payload, []byte("\r\n\r\n")); i > 0 {
		head = payload[:i]
	}
	if !hasMethod(head) {
		return "", "", false
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 {
		return "", "", false
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return "", "", false
	}
	target := string(parts[1])
	for _, l := range lines[1:] {
		if len(l) > 5 && bytes.EqualFold(l[:5], []byte("host:")) {
			host = strings.TrimSpace(string(l[5:]))
		}
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return host, target, true
	}
	if host == "" {
		return "", "", false
	}
	if target == "" {
		target = "/"
	}
	return host, "http://" + host + target, true
}

// HostOnly 解析 Host 头（用于连续请求之间复用）
func HostOnly(payload []byte) string {
	for _, line := range bytes.Split(payload, []byte("\r\n")) {
		if len(line) > 5 && bytes.EqualFold(line[:5], []byte("host:")) {
			return strings.TrimSpace(string(line[5:]))
		}
	}
	return ""
}

func hasMethod(b []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	// 有些客户端首行被截断，放宽：前 16 字节内含 "HTTP/1."
	if i := bytes.Index(b, []byte("HTTP/1.")); i > 0 && i < 64 {
		return true
	}
	return false
}

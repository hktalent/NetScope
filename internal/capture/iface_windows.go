//go:build windows

package capture

// Windows 上默认路由所在网卡由 pcap 提供的列表 + 首个有 IPv4 的非回环网卡决定
func defaultIfaceOS() string { return "" }

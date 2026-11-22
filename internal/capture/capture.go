package capture

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type Packet struct {
	Ts      time.Time
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string // TCP / UDP
	IPLen   int
	Payload []byte
	DNS     *layers.DNS
	TCP     *layers.TCP
}

type Handler func(p *Packet)

type Engine struct {
	Handle   *pcap.Handle
	Name     string
	localIPs map[string]bool
	Local    []string
}

// Open 打开网卡并设置 BPF 过滤（只看 TCP 与 UDP）
func Open(iface string, snaplen int32) (*Engine, error) {
	if iface == "" || iface == "auto" {
		iface = DefaultInterface()
	}
	h, err := pcap.OpenLive(iface, snaplen, true, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("打开网卡 %s 失败（macOS 需 access_bpf 组或 sudo，Linux 需 CAP_NET_RAW，Windows 需 Npcap+管理员）: %w", iface, err)
	}
	if err := h.SetBPFFilter("tcp or udp"); err != nil {
		h.Close()
		return nil, fmt.Errorf("设置 BPF 过滤失败: %w", err)
	}
	return &Engine{Handle: h, Name: iface, localIPs: localIPsOf(iface)}, nil
}

func (e *Engine) IsLocal(ip string) bool { return e.localIPs[ip] }

func (e *Engine) Close() { if e.Handle != nil { e.Handle.Close() } }

// Run 阻塞解码，直到 stop 关闭或出错
func (e *Engine) Run(h Handler, stop <-chan struct{}) error {
	src := gopacket.NewPacketSource(e.Handle, e.Handle.LinkType())
	src.NoCopy = false
	pkts := src.Packets()
	for {
		select {
		case <-stop:
			return nil
		case pkt, ok := <-pkts:
			if !ok {
				return nil
			}
			if p := decode(pkt); p != nil {
				h(p)
			}
		}
	}
}

func decode(pkt gopacket.Packet) *Packet {
	out := &Packet{Ts: pkt.Metadata().Timestamp}
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		out.SrcIP, out.DstIP, out.IPLen = ip.SrcIP.String(), ip.DstIP.String(), int(ip.Length)
	case *layers.IPv6:
		out.SrcIP, out.DstIP, out.IPLen = ip.SrcIP.String(), ip.DstIP.String(), len(ip.Contents)+40
		// 只关心应用层，IPv6 扩展头后面交给 gopacket
	default:
		return nil
	}
	switch t := pkt.TransportLayer().(type) {
	case *layers.TCP:
		out.Proto = "TCP"
		out.SrcPort, out.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		out.Payload = t.Payload
		out.TCP = t
		if d := pkt.Layer(layers.LayerTypeDNS); d != nil {
			out.DNS = d.(*layers.DNS)
		}
	case *layers.UDP:
		out.Proto = "UDP"
		out.SrcPort, out.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		out.Payload = t.Payload
		if d := pkt.Layer(layers.LayerTypeDNS); d != nil {
			out.DNS = d.(*layers.DNS)
		}
	default:
		return nil
	}
	if out.IPLen <= 0 {
		out.IPLen = len(pkt.Data())
	}
	return out
}

func localIPsOf(iface string) map[string]bool {
	m := map[string]bool{"127.0.0.1": true, "::1": true}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return m
	}
	for _, d := range devs {
		if d.Name != iface {
			continue
		}
		for _, a := range d.Addresses {
			if a.IP != nil {
				m[a.IP.String()] = true
			}
		}
	}
	if len(m) <= 2 { // 没拿到，退化为全部网卡
		for _, d := range devs {
			for _, a := range d.Addresses {
				if a.IP != nil {
					m[a.IP.String()] = true
				}
			}
		}
	}
	return m
}

// LocalAddresses 列出该网卡地址（展示用）
func (e *Engine) LocalAddresses() []string {
	var out []string
	for k := range e.localIPs {
		if k != "127.0.0.1" && k != "::1" && !strings.Contains(k, ":") {
			out = append(out, k)
		}
	}
	return out
}

// DefaultInterface 取默认路由所在网卡
func DefaultInterface() string {
	if name := defaultIfaceOS(); name != "" {
		if _, err := net.InterfaceByName(name); err == nil {
			log.Printf("自动选择网卡: %s", name)
			return name
		}
	}
	// 退化为「第一个有 IPv4 的非回环网卡」
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, i := range ifaces {
			if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					log.Printf("自动选择网卡: %s", i.Name)
					return i.Name
				}
			}
		}
	}
	return "en0"
}

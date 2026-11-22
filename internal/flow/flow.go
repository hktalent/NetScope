package flow

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket/layers"

	"netscope/internal/capture"
	"netscope/internal/dnsmap"
	"netscope/internal/geo"
	"netscope/internal/httpurl"
	"netscope/internal/model"
	"netscope/internal/proc"
	"netscope/internal/sni"
)

const (
	idleTTL   = 90 * time.Second // 无流量多久后从表里淘汰
	closeTTL  = 30 * time.Second // 已关闭连接的保留时间
	histLen   = 60               // 速率曲线点数（秒）
	ewmaAlpha = 0.3
)

type conn struct {
	m          model.Conn
	prevBytes  uint64
	prevTick   time.Time
	sniDone    bool
	lastHost   string
	lastActive time.Time
	closed     bool
	closedAt   time.Time
}

type Table struct {
	mu    sync.Mutex
	conns map[string]*conn

	eng  *capture.Engine
	dns  *dnsmap.Map
	geo  *geo.Geo
	proc *proc.Tracker

	max     int
	histD   []float64
	histU   []float64
	lastRUp float64
	lastRDn float64

	totalBytes uint64
	lastTick   time.Time
}

func New(eng *capture.Engine, d *dnsmap.Map, g *geo.Geo, p *proc.Tracker, max int) *Table {
	if max <= 0 {
		max = 5000
	}
	return &Table{
		conns:    map[string]*conn{},
		eng:      eng,
		dns:      d,
		geo:      g,
		proc:     p,
		max:      max,
		histD:    make([]float64, 0, histLen),
		histU:    make([]float64, 0, histLen),
		lastTick: time.Now(),
	}
}

// Handle 处理一个抓到的包（热路径）
func (t *Table) Handle(p *capture.Packet) {
	now := p.Ts
	if now.IsZero() {
		now = time.Now()
	}
	if p.DNS != nil {
		t.dns.Learn(p.DNS, now)
	}

	srcLocal, dstLocal := t.eng.IsLocal(p.SrcIP), t.eng.IsLocal(p.DstIP)
	var localIP, remoteIP string
	var localPort, remotePort uint16
	up := false
	switch {
	case srcLocal && dstLocal: // loopback：发起方视为本机客户端
		localIP, remoteIP = p.SrcIP, p.DstIP
		localPort, remotePort = p.SrcPort, p.DstPort
		up = true
	case srcLocal:
		localIP, remoteIP = p.SrcIP, p.DstIP
		localPort, remotePort = p.SrcPort, p.DstPort
		up = true
	case dstLocal:
		localIP, remoteIP = p.DstIP, p.SrcIP
		localPort, remotePort = p.DstPort, p.SrcPort
		up = false
	default:
		return // 非本机流量（混杂模式下看到的邻居），不计入
	}

	// UDP 只关心 DNS(53) 与 QUIC(443)，避免 mdns/广播干扰
	if p.Proto == "UDP" {
		if !(p.SrcPort == 53 || p.DstPort == 53 || p.SrcPort == 443 || p.DstPort == 443) {
			return
		}
	}

	key := makeKey(p.Proto, localIP, localPort, remoteIP, remotePort)

	t.mu.Lock()
	c, ok := t.conns[key]
	if !ok {
		if len(t.conns) >= t.max {
			t.evictLocked(now)
		}
		c = &conn{
			m: model.Conn{
				Key:        key,
				LocalIP:    localIP,
				LocalPort:  localPort,
				IP:         remoteIP,
				Port:       remotePort,
				Proto:      p.Proto,
				State:      "NEW",
				First:      now,
				AppProto:   guessProto(p),
				CountryCode: "",
			},
			prevTick: now,
		}
		if d := t.dns.Lookup(remoteIP, now); d != "" {
			c.m.Domain = d
		}
		t.conns[key] = c
		t.enrichLocked(c, now)
	}
	c.lastActive = now
	c.m.Last = now
	if up {
		c.m.BytesUp += uint64(p.IPLen)
		c.m.PktsUp++
	} else {
		c.m.BytesDown += uint64(p.IPLen)
		c.m.PktsDown++
	}
	if p.DNS != nil && (p.SrcPort == 53 || p.DstPort == 53) {
		c.m.AppProto = "DNS"
	}
	if p.TCP != nil {
		switch {
		case p.TCP.RST:
			c.m.State = "RESET"
			c.closed, c.closedAt = true, now
		case p.TCP.FIN:
			c.m.State = "CLOSING"
		case p.TCP.SYN && p.TCP.ACK:
			if c.m.State == "NEW" || c.m.State == "SYN" {
				c.m.State = "ESTABLISHED"
			}
		case p.TCP.SYN:
			c.m.State = "SYN"
		default:
			if c.m.State == "NEW" || c.m.State == "SYN" {
				c.m.State = "ESTABLISHED"
			}
		}
	} else {
		c.m.State = "ESTABLISHED"
	}

	// 应用层识别：TLS SNI / HTTP URL
	if len(p.Payload) > 0 {
		if isTLS(p.Payload) {
			if !c.sniDone {
				if name, _, ok := sni.ParseClientHello(p.Payload); ok && name != "" {
					c.m.Domain = name
					c.m.AppProto = "TLS"
					c.sniDone = true
				}
			}
		} else if h, u, ok := httpurl.ParseRequest(p.Payload); ok {
			c.m.AppProto = "HTTP"
			if h != "" {
				c.lastHost = h
			}
			if u != "" {
				c.m.URL = u
			}
		}
	}
	t.totalBytes += uint64(p.IPLen)
	t.mu.Unlock()
}

// Tick 每秒调用：算速率、补国家/进程、回收
func (t *Table) Tick() (upRate, downRate float64) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	dt := now.Sub(t.lastTick).Seconds()
	if dt <= 0 {
		dt = 1
	}
	var sumUp, sumDn float64
	for k, c := range t.conns {
		total := c.m.BytesUp + c.m.BytesDown
		d := float64(total-c.prevBytes) / dt
		c.prevBytes = total
		c.prevTick = now

		// 按方向拆分更精确：用累计占比估算
		upShare := 0.0
		if total > 0 {
			upShare = float64(c.m.BytesUp) / float64(total)
		}
		rU := d * upShare
		rD := d * (1 - upShare)
		_ = rU
		_ = rD
		instant := d
		c.m.RateUp = ewma(c.m.RateUp, instant*upShare)
		c.m.RateDown = ewma(c.m.RateDown, instant*(1-upShare))
		sumUp += c.m.RateUp
		sumDn += c.m.RateDown

		// 补域名 / 国家 / 进程
		if c.m.Domain == "" {
			if dm := t.dns.Lookup(c.m.IP, now); dm != "" {
				c.m.Domain = dm
			}
		}
		t.enrichLocked(c, now)

		// 回收
		idle := now.Sub(c.lastActive)
		if c.closed {
			if now.Sub(c.closedAt) > closeTTL {
				delete(t.conns, k)
			}
		} else if idle > idleTTL {
			delete(t.conns, k)
		}
	}
	t.lastTick = now
	t.lastRUp, t.lastRDn = sumUp, sumDn
	t.histD = appendCap(t.histD, sumDn)
	t.histU = appendCap(t.histU, sumUp)
	return sumUp, sumDn
}

// groupByDomainIP 把「同一域名 + 同一 IP」的多条连接合并为一行
// 域名与 IP 均相同的才算同一目标；无域名的按 IP 聚合
func groupByDomainIP(in []*model.Conn) []*model.Conn {
	m := make(map[string]*model.Conn, len(in))
	order := make([]string, 0, len(in))
	for _, c := range in {
		k := c.Domain + "\x00" + c.IP
		g, ok := m[k]
		if !ok {
			cp := *c
			cp.Merged = 1
			m[k] = &cp
			order = append(order, k)
			continue
		}
		g.BytesUp += c.BytesUp
		g.BytesDown += c.BytesDown
		g.PktsUp += c.PktsUp
		g.PktsDown += c.PktsDown
		g.RateUp += c.RateUp
		g.RateDown += c.RateDown
		if c.First.Before(g.First) || g.First.IsZero() {
			g.First = c.First
		}
		if c.Last.After(g.Last) {
			g.Last = c.Last
		}
		if g.URL == "" && c.URL != "" {
			g.URL = c.URL
		}
		if g.AppProto == "" || g.AppProto == "-" {
			if c.AppProto != "" && c.AppProto != "-" {
				g.AppProto = c.AppProto
			}
		}
		if c.State == "ESTABLISHED" {
			g.State = "ESTABLISHED"
		}
		// App 取流量最大的那条连接，避免同一目标显示成空
		if c.App != "" && (g.App == "" || c.Bytes > g.Bytes) {
			g.App, g.PID, g.AppPath = c.App, c.PID, c.AppPath
		}
		g.Merged++
	}
	out := make([]*model.Conn, 0, len(order))
	for _, k := range order {
		g := m[k]
		g.Bytes = g.BytesUp + g.BytesDown
		g.Rate = g.RateUp + g.RateDown
		// 合并行不再展示单个本地端口（多个端口已无意义）
		g.LocalPort = 0
		// 域名服务方是多 App 时，标注数量
		out = append(out, g)
	}
	return out
}

// Snapshot 生成前端需要的视图（按速率降序）
func (t *Table) Snapshot(top int) model.Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]*model.Conn, 0, len(t.conns))
	now := time.Now()
	apps := map[string]bool{}
	countries := map[string]bool{}
	active := 0
	for _, c := range t.conns {
		if now.Sub(c.lastActive) > idleTTL {
			continue
		}
		if now.Sub(c.lastActive) < 20*time.Second {
			active++
		}
		cp := c.m
		cp.URL = buildURL(&cp)
		cp.Fill()
		if cp.App != "" {
			apps[cp.App] = true
		}
		if cp.Country != "" && cp.Country != "局域网" {
			countries[cp.Country] = true
		}
		out = append(out, &cp)
	}
	// 相同「域名 + IP」合并成一行（多连接汇总）
	out = groupByDomainIP(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rate != out[j].Rate {
			return out[i].Rate > out[j].Rate
		}
		return out[i].Bytes > out[j].Bytes
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return model.Snapshot{
		Summary: model.Summary{
			Iface:      t.eng.Name,
			RateUp:     t.lastRUp,
			RateDown:   t.lastRDn,
			ConnCount:  len(t.conns),
			Active:     active,
			Apps:       len(apps),
			Countries:  len(countries),
			TotalBytes: t.totalBytes,
			HistDown:   append([]float64{}, t.histD...),
			HistUp:     append([]float64{}, t.histU...),
			At:         now,
		},
		Conns: out,
	}
}

// enrichLocked 补国家与进程（幂等、带缓存）
func (t *Table) enrichLocked(c *conn, now time.Time) {
	if c.m.CountryCode == "" && c.m.Country == "" {
		if isPrivate(c.m.IP) {
			c.m.Country, c.m.CountryCode = "局域网", "LAN"
		} else if r := t.geo.Lookup(c.m.IP); r.Code != "" || r.Country != "" {
			c.m.Country, c.m.CountryCode = r.Country, r.Code
		}
	}
	if c.m.App == "" && t.proc != nil {
		if info := t.proc.Lookup(c.m.LocalPort); info.PID > 0 {
			c.m.App, c.m.PID, c.m.AppPath = info.Name, info.PID, info.Path
		}
	}
}

func (t *Table) evictLocked(now time.Time) {
	// 优先淘汰已关闭/最久未活动的
	var victim string
	var worst time.Time
	for k, c := range t.conns {
		if c.closed {
			victim = k
			break
		}
		if victim == "" || c.lastActive.Before(worst) {
			victim, worst = k, c.lastActive
		}
	}
	if victim != "" {
		delete(t.conns, victim)
	}
}

func makeKey(proto, localIP string, localPort uint16, remoteIP string, remotePort uint16) string {
	if localIP <= remoteIP {
		return proto + "|" + localIP + ":" + itoa(localPort) + "|" + remoteIP + ":" + itoa(remotePort)
	}
	return proto + "|" + remoteIP + ":" + itoa(remotePort) + "|" + localIP + ":" + itoa(localPort)
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	buf := make([]byte, 0, 5)
	for p > 0 {
		buf = append([]byte{byte('0' + p%10)}, buf...)
		p /= 10
	}
	return string(buf)
}

func guessProto(p *capture.Packet) string {
	if p.Proto == "UDP" {
		if p.SrcPort == 53 || p.DstPort == 53 {
			return "DNS"
		}
		if p.SrcPort == 443 || p.DstPort == 443 {
			return "QUIC"
		}
		return "UDP"
	}
	switch {
	case p.SrcPort == 443 || p.DstPort == 443:
		return "TLS" // 443 基本必为 TLS/HTTP2，SNI 到达后会二次确认
	case p.SrcPort == 80 || p.DstPort == 80:
		return "-" // 端口 80 未解析到 HTTP 请求前不谎报
	}
	return "-"
}

func buildURL(c *model.Conn) string {
	if c.URL != "" {
		return c.URL
	}
	if c.Domain == "" {
		return ""
	}
	switch c.AppProto {
	case "QUIC":
		return "quic://" + c.Domain
	case "DNS":
		return ""
	default:
		return "https://" + c.Domain
	}
}

func isTLS(b []byte) bool {
	return len(b) > 5 && b[0] == 0x16 && b[1] == 0x03
}

func ewma(prev, cur float64) float64 {
	if prev == 0 {
		return cur
	}
	return ewmaAlpha*cur + (1-ewmaAlpha)*prev
}

func appendCap(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > histLen {
		s = s[len(s)-histLen:]
	}
	return s
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

var _ = layers.LayerTypeTCP

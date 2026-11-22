package dnsmap

import (
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket/layers"
)

type entry struct {
	domain string
	expire time.Time
}

// Map 保存 IP → 域名 的映射（由 DNS 应答学习，带 TTL）
type Map struct {
	mu   sync.RWMutex
	byIP map[string]entry
}

func New() *Map { return &Map{byIP: map[string]entry{}} }

// Learn 从一条 DNS 报文学习映射
func (m *Map) Learn(d *layers.DNS, now time.Time) {
	if d == nil {
		return
	}
	qname := ""
	if len(d.Questions) > 0 {
		qname = string(d.Questions[0].Name)
	}
	if !d.QR || len(d.Answers) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range d.Answers {
		name := string(a.Name)
		// 优先用「用户实际查询的域名」，而不是 CNAME 链末端（如 ts3.tc.mm.bing.net.eo.dnse3.com）
		if qname != "" {
			name = qname
		} else if name == "" {
			continue
		}
		var ip string
		switch a.Type {
		case layers.DNSTypeA:
			ip = a.IP.String()
		case layers.DNSTypeAAAA:
			ip = a.IP.String()
		}
		if ip == "" || ip == "<nil>" {
			continue
		}
		ttl := time.Duration(a.TTL) * time.Second
		if ttl < 10*time.Second {
			ttl = 10 * time.Second
		}
		if ttl > 10*time.Minute {
			ttl = 10 * time.Minute
		}
		m.byIP[ip] = entry{domain: strings.ToLower(strings.TrimSuffix(name, ".")), expire: now.Add(ttl)}
	}
}

// Lookup 查询 IP 对应域名
func (m *Map) Lookup(ip string, now time.Time) string {
	m.mu.RLock()
	e, ok := m.byIP[ip]
	m.mu.RUnlock()
	if !ok || now.After(e.expire) {
		return ""
	}
	return e.domain
}

// GC 清理过期项
func (m *Map) GC(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.byIP {
		if now.After(v.expire) {
			delete(m.byIP, k)
		}
	}
}

func (m *Map) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byIP)
}

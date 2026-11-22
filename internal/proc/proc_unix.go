//go:build !windows

package proc

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Info struct {
	PID  int
	Name string
	Path string // 可执行文件绝对路径
}

// Tracker 定期采样「本地端口 → 进程」映射（基于 lsof，实测 0.5s/次）
type Tracker struct {
	mu       sync.RWMutex
	byPort   map[uint16]Info
	interval time.Duration
	lastOK   time.Time
	lastErr  string
	pathCache map[int]string // pid → 可执行文件路径
}

func New(interval time.Duration) *Tracker {
	return &Tracker{byPort: map[uint16]Info{}, pathCache: map[int]string{}, interval: interval}
}

func (t *Tracker) Run(ctx context.Context) {
	t.refresh()
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.refresh()
		}
	}
}

func (t *Tracker) Lookup(port uint16) Info {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byPort[port]
}

func (t *Tracker) LastRefresh() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastOK
}

func (t *Tracker) refresh() {
	var buf bytes.Buffer
	cmd := exec.Command("lsof", "-nP", "-i")
	cmd.Stdout = &buf
	err := cmd.Run()
	// lsof 对部分无权限进程会返回退出码 1，但 stdout 仍是有效数据
	if err != nil && buf.Len() == 0 {
		t.mu.Lock()
		t.lastErr = err.Error()
		t.mu.Unlock()
		return
	}
	m := make(map[uint16]Info, 2048)
	for _, line := range strings.Split(buf.String(), "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		if f[7] != "TCP" && f[7] != "UDP" {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil || pid <= 0 {
			continue
		}
		name := f[0]
		localPort := parseLocalPort(f[8])
		if localPort == 0 {
			continue
		}
		// 同一端口多个候选时，优先保留非 * 的（已建立连接优先于监听）
		if _, exists := m[localPort]; !exists || strings.Contains(f[8], "->") {
			m[localPort] = Info{PID: pid, Name: name}
		}
	}
	// 为新出现的 PID 解析可执行文件路径（带缓存，避免重复系统调用）
	t.mu.RLock()
	cache := t.pathCache
	t.mu.RUnlock()
	for port, inf := range m {
		if path, ok := cache[inf.PID]; ok {
			inf.Path = path
			m[port] = inf
			continue
		}
		inf.Path = resolvePath(inf.PID)
		m[port] = inf
		cache[inf.PID] = inf.Path
	}

	t.mu.Lock()
	t.byPort = m
	t.pathCache = cache
	t.lastOK = time.Now()
	t.lastErr = ""
	t.mu.Unlock()
}

// parseLocalPort 从 lsof NAME 字段取本地端口
// 形如 192.168.1.10:57994->1.2.3.4:80 / *:8082 / [::1]:8899 / 10.0.0.1:53
func parseLocalPort(name string) uint16 {
	if i := strings.Index(name, "->"); i > 0 {
		name = name[:i]
	}
	i := strings.LastIndex(name, ":")
	if i < 0 || i+1 >= len(name) {
		return 0
	}
	p, err := strconv.Atoi(strings.TrimRight(name[i+1:], " "))
	if err != nil {
		return 0
	}
	return uint16(p)
}

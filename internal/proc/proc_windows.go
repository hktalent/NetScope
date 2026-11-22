//go:build windows

package proc

import (
	"context"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	gproc "github.com/shirou/gopsutil/v4/process"
)

type Info struct {
	PID  int
	Name string
	Path string
}

type Tracker struct {
	mu       sync.RWMutex
	byPort   map[uint16]Info
	interval time.Duration
	lastOK   time.Time
}

func New(interval time.Duration) *Tracker {
	return &Tracker{byPort: map[uint16]Info{}, interval: interval}
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
	conns, err := gnet.Connections("all")
	if err != nil {
		return
	}
	m := make(map[uint16]Info, 2048)
	names := map[int32]string{}
	for _, c := range conns {
		port := uint16(c.Laddr.Port)
		if port == 0 {
			continue
		}
		name, ok := names[c.Pid]
		if !ok {
			exe := ""
			if p, e := gproc.NewProcess(c.Pid); e == nil {
				name, _ = p.Name()
				exe, _ = p.Exe()
			}
			names[c.Pid] = name
			m[port] = Info{PID: int(c.Pid), Name: name, Path: exe}
			continue
		}
		m[port] = Info{PID: int(c.Pid), Name: name}
	}
	t.mu.Lock()
	t.byPort = m
	t.lastOK = time.Now()
	t.mu.Unlock()
}

package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"netscope/internal/flow"
	"netscope/internal/model"
	"netscope/web"
)

type Server struct {
	tab *flow.Table
	top int
}

func New(tab *flow.Table, top int) *Server {
	if top <= 0 {
		top = 300
	}
	return &Server{tab: tab, top: top}
}

func (s *Server) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.Handle("/app.js", http.FileServer(http.FS(web.FS)))
	mux.Handle("/style.css", http.FileServer(http.FS(web.FS)))
	mux.Handle("/footer.js", http.FileServer(http.FS(web.FS)))
	mux.HandleFunc("/api/snapshot", s.snapshot)
	mux.HandleFunc("/api/stream", s.stream)
	mux.HandleFunc("/api/export.csv", s.exportCSV)
	// 端口释放有延迟（刚重启时常见），重试几次再放弃
	var ln net.Listener
	var err error
	for i := 0; i < 12; i++ {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	log.Printf("Web UI: http://%s", addr)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := web.FS.ReadFile("index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	top := s.top
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			top = n
		}
	}
	snap := s.tab.Snapshot(top)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(snap)
}

// stream 用 SSE 每秒推一次快照（比 WebSocket 少一层依赖，断线自动重连）
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()

	write := func() bool {
		snap := s.tab.Snapshot(s.top)
		b, err := json.Marshal(snap)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !write() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-tk.C:
			if !write() {
				return
			}
		}
	}
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	snap := s.tab.Snapshot(0)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="netscope-conns.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	cw.Write([]string{"域名", "IP", "端口", "国家", "App", "PID", "程序路径", "协议", "数据(字节)", "速率(B/s)", "URL", "状态", "首次", "最后"})
	for _, c := range snap.Conns {
		cw.Write([]string{
			c.Domain, c.IP, strconv.Itoa(int(c.Port)), c.Country, c.App, strconv.Itoa(c.PID), c.AppPath,
			c.Proto + "/" + c.AppProto, strconv.FormatUint(c.Bytes, 10),
			fmt.Sprintf("%.2f", c.Rate), c.URL, c.State,
			c.First.Format("15:04:05"), c.Last.Format("15:04:05"),
		})
	}
}

var _ = model.Conn{}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"netscope/internal/capture"
	"netscope/internal/dnsmap"
	"netscope/internal/flow"
	"netscope/internal/geo"
	"netscope/internal/proc"
	"netscope/internal/server"
)

// version 由构建注入：go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

func main() {
	var (
		iface   = flag.String("iface", "auto", "网卡名（auto=默认路由网卡）")
		port    = flag.Int("port", 8899, "Web 端口")
		top     = flag.Int("top", 300, "每次推送的最大行数")
		maxConn = flag.Int("max", 5000, "内存中最多保留的连接数")
		geoPath = flag.String("geo", "", "GeoIP 库路径（留空自动下载到 data/）")
		noGeo   = flag.Bool("no-geo", false, "禁用 GeoIP（不下载、不显示国家）")
		lsofInt = flag.Duration("lsof", 3*time.Second, "进程归因采样间隔")
		showLst = flag.Bool("list", false, "只列出网卡后退出")
		showVer = flag.Bool("version", false, "显示版本后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	if *showLst {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		for _, d := range devs {
			fmt.Printf("%-10s %v\n", d.Name, addrList(d.Addresses))
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 1. 抓包
	eng, err := capture.Open(*iface, 262144)
	if err != nil {
		log.Fatalf("抓包初始化失败: %v", err)
	}
	defer eng.Close()
	log.Printf("抓包网卡: %s  本机地址: %v", eng.Name, eng.LocalAddresses())

	// 2. GeoIP（单一实例，后台下载完成后原地加载，流表持有的指针始终有效）
	g := geo.New()
	if !*noGeo {
		wd, _ := os.Getwd()
		p := *geoPath
		if p == "" {
			p = filepath.Join(wd, "data", "dbip-country-lite.mmdb")
		}
		if _, err := os.Stat(p); err == nil {
			if err := g.Load(p); err != nil {
				log.Printf("GeoIP 库加载失败: %v", err)
			}
		} else {
			go func() {
				path, err := geo.EnsureDB(filepath.Dir(p))
				if err != nil {
					log.Printf("GeoIP 库不可用: %v", err)
					return
				}
				if err := g.Load(path); err != nil {
					log.Printf("GeoIP 库加载失败: %v", err)
				}
			}()
		}
	}

	// 3. 进程归因
	tracker := proc.New(*lsofInt)
	go tracker.Run(ctx)

	// 4. 流表
	dns := dnsmap.New()
	tab := flow.New(eng, dns, g, tracker, *maxConn)

	// 5. 抓包循环
	go func() {
		stop := make(chan struct{})
		go func() { <-ctx.Done(); close(stop) }()
		if err := eng.Run(tab.Handle, stop); err != nil {
			log.Printf("抓包循环结束: %v", err)
		}
	}()

	// 6. 每秒算速率 + 周期 GC
	go func() {
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		gc := time.NewTicker(30 * time.Second)
		defer gc.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				tab.Tick()
			case <-gc.C:
				dns.GC(time.Now())
			}
		}
	}()

	// 7. Web
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(*port))
	srv := server.New(tab, *top)
	go func() {
		if err := srv.Listen(addr); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Web 服务启动失败（端口 %d 可能被占用）: %v", *port, err)
		}
	}()

	fmt.Printf("\n  NetScope %s 已启动 →  http://%s\n  网卡 %s · 按 Ctrl+C 退出\n\n", version, addr, eng.Name)
	<-ctx.Done()
	log.Println("正在退出…")
	time.Sleep(300 * time.Millisecond)
}

func addrList(as []pcap.InterfaceAddress) string {
	var out string
	for _, a := range as {
		if a.IP != nil {
			out += a.IP.String() + " "
		}
	}
	return out
}

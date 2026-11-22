package geo

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

type Geo struct {
	mu   sync.RWMutex
	rd   *maxminddb.Reader
	path string
	// 内存缓存，避免重复查库
	cache map[string]Result
}

type Result struct {
	Country string
	Code    string
}

func Open(path string) *Geo {
	g := New()
	if path != "" {
		if err := g.Load(path); err != nil {
			log.Printf("GeoIP 未加载（国家列将显示 -）: %v", err)
		}
	}
	return g
}

func New() *Geo { return &Geo{cache: map[string]Result{}} }

// Load 载入库文件（可后置调用，例如后台下载完成后再加载）
func (g *Geo) Load(path string) error {
	rd, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	g.mu.Lock()
	if g.rd != nil {
		g.rd.Close()
	}
	g.rd = rd
	g.path = path
	g.cache = map[string]Result{}
	g.mu.Unlock()
	log.Printf("GeoIP 已加载: %s", path)
	return nil
}

func (g *Geo) Ready() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.rd != nil
}

func (g *Geo) Lookup(ipStr string) Result {
	g.mu.RLock()
	if c, ok := g.cache[ipStr]; ok {
		g.mu.RUnlock()
		return c
	}
	rd := g.rd
	g.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if rd == nil || ip == nil {
		return Result{Country: "", Code: ""}
	}
	var rec record
	res := Result{}
	if err := rd.Lookup(ip, &rec); err == nil && rec.Country.ISOCode != "" {
		res.Code = rec.Country.ISOCode
		res.Country = rec.Country.Names["zh-CN"]
		if res.Country == "" {
			res.Country = rec.Country.Names["en"]
		}
	}
	g.mu.Lock()
	if len(g.cache) > 50000 {
		g.cache = map[string]Result{}
	}
	g.cache[ipStr] = res
	g.mu.Unlock()
	return res
}

// EnsureDB 若库文件不存在则自动下载 DB-IP Lite（免注册，CC BY 4.0）
func EnsureDB(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "dbip-country-lite.mmdb")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		return path, nil
	}
	now := time.Now()
	for i := 0; i < 4; i++ {
		ym := now.AddDate(0, -i, 0).Format("2006-01")
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz", ym)
		if err := download(url, path); err == nil {
			log.Printf("已下载 GeoIP 库: %s (%s)", path, ym)
			return path, nil
		} else {
			log.Printf("下载 %s 失败: %v", url, err)
		}
	}
	return "", fmt.Errorf("自动下载 GeoIP 库失败，请手动放入 %s", path)
}

func download(url, dst string) error {
	c := &http.Client{Timeout: 90 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, gz); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, dst)
}

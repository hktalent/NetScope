package model

import "time"

// Conn 是一条连接（双向聚合后）的可展示视图
type Conn struct {
	Key      string `json:"key"`
	LocalIP  string `json:"localIp"`
	LocalPort uint16 `json:"localPort"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`

	Proto    string `json:"proto"`    // TCP / UDP
	AppProto string `json:"appProto"` // TLS / HTTP / QUIC / DNS / -

	Domain      string `json:"domain"`
	URL         string `json:"url"`
	Country     string `json:"country"`
	CountryCode string `json:"cc"`

	App     string `json:"app"`
	PID     int    `json:"pid"`
	AppPath string `json:"appPath"` // 可执行文件完整路径

	BytesUp   uint64 `json:"bytesUp"`
	BytesDown uint64 `json:"bytesDown"`
	Bytes     uint64 `json:"bytes"`
	PktsUp    uint64 `json:"pktsUp"`
	PktsDown  uint64 `json:"pktsDown"`

	RateUp   float64 `json:"rateUp"`
	RateDown float64 `json:"rateDown"`
	Rate     float64 `json:"rate"`

	Merged int      `json:"merged"` // 合并了几条底层连接
	State string    `json:"state"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`

	// 内部状态（不序列化）
	tickBytes uint64
	rateUp    float64
	rateDown  float64
	lastHost  string
	closed    bool
	geoDone   bool
	procDone  bool
	hasSni    bool
}

// Fill 由内部状态补齐展示字段
func (c *Conn) Fill() {
	c.Bytes = c.BytesUp + c.BytesDown
	c.Rate = c.RateUp + c.RateDown
}

type Summary struct {
	Iface     string    `json:"iface"`
	RateUp    float64   `json:"rateUp"`
	RateDown  float64   `json:"rateDown"`
	ConnCount int       `json:"connCount"`
	Active    int       `json:"active"`
	Apps      int       `json:"apps"`
	Countries int       `json:"countries"`
	TotalBytes uint64   `json:"totalBytes"`
	HistDown  []float64 `json:"histDown"`
	HistUp    []float64 `json:"histUp"`
	At        time.Time `json:"at"`
}

type Snapshot struct {
	Summary
	Conns []*Conn `json:"conns"`
}

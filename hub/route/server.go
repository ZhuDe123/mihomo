package route

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/cors"
	"github.com/metacubex/chi/middleware"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

var (
	uiPath = ""

	httpServer *http.Server
	tlsServer  *http.Server
	unixServer *http.Server
	pipeServer *http.Server

	embedMode = false
)

func SetEmbedMode(embed bool) {
	embedMode = embed
}

type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	OSLimit uint64 `json:"oslimit"` // maybe we need it in the future
}

type Config struct {
	Addr           string
	TLSAddr        string
	UnixAddr       string
	PipeAddr       string
	Secret         string
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
	EchKey         string
	DohServer      string
	IsDebug        bool
	Cors           Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

func (c Cors) Apply(r chi.Router) {
	r.Use(cors.New(cors.Options{
		AllowedOrigins:      c.AllowOrigins,
		AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:      []string{"Content-Type", "Authorization"},
		AllowPrivateNetwork: c.AllowPrivateNetwork,
		MaxAge:              300,
	}).Handler)
}

func ReCreateServer(cfg *Config) {
	go start(cfg)
	go startTLS(cfg)
	go startUnix(cfg)
	if inbound.SupportNamedPipe {
		go startPipe(cfg)
	}
}

func SetUIPath(path string) {
	uiPath = C.Path.Resolve(path)
}

func router(isDebug bool, secret string, dohServer string, cors Cors) *chi.Mux {
	r := chi.NewRouter()
	cors.Apply(r)
	if isDebug {
		r.Mount("/debug", func() http.Handler {
			r := chi.NewRouter()
			r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
				debug.FreeOSMemory()
			})
			handler := middleware.Profiler
			r.Mount("/", handler())
			return r
		}())
	}
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}
		r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/traffic/latest", trafficLatest)     // 新增：非流式流量数据
		r.Get("/traffic/summary", trafficSummary)   // 新增：聚合流量统计（推荐接口）
		r.Get("/traffic/ip", trafficIPStats)        // 新增：IP 流量统计（聚合）
		r.Get("/traffic/closed", closedConnections) // 新增：获取最近关闭的连接
		r.Get("/traffic/ip/accumulated", ipAccumulatedStats)
		r.Get("/memory", memory)
		r.Get("/version", version)
		r.Mount("/configs", configRouter())
		r.Mount("/proxies", proxyRouter())
		r.Mount("/group", groupRouter())
		r.Mount("/rules", ruleRouter())
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/cache", cacheRouter())
		r.Mount("/dns", dnsRouter())
		if !embedMode { // disallow restart in embed mode
			r.Mount("/restart", restartRouter())
		}
		r.Mount("/upgrade", upgradeRouter())
		addExternalRouters(r)

	})

	if uiPath != "" {
		r.Group(func(r chi.Router) {
			fs := http.StripPrefix("/ui", http.FileServer(http.Dir(uiPath)))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

func start(cfg *Config) {
	// first stop existing server
	if httpServer != nil {
		_ = httpServer.Close()
		httpServer = nil
	}

	// handle addr
	if len(cfg.Addr) > 0 {
		l, err := inbound.Listen("tcp", cfg.Addr)
		if err != nil {
			log.Errorln("External controller listen error: %s", err)
			return
		}
		log.Infoln("RESTful API listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		}
		httpServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller serve error: %s", err)
		}
	}
}

func startTLS(cfg *Config) {
	// first stop existing server
	if tlsServer != nil {
		_ = tlsServer.Close()
		tlsServer = nil
	}

	// handle tlsAddr
	if len(cfg.TLSAddr) > 0 {
		certLoader, err := ca.NewTLSKeyPairLoader(cfg.Certificate, cfg.PrivateKey)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		l, err := inbound.Listen("tcp", cfg.TLSAddr)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		log.Infoln("RESTful API tls listening at: %s", l.Addr().String())
		tlsConfig := &tls.Config{Time: ntp.Now}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}
		tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(cfg.ClientAuthType)
		if len(cfg.ClientAuthCert) > 0 {
			if tlsConfig.ClientAuth == tls.NoClientCert {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
		if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			pool, err := ca.LoadCertificates(cfg.ClientAuthCert)
			if err != nil {
				log.Errorln("External controller tls listen error: %s", err)
				return
			}
			tlsConfig.ClientCAs = pool
		}

		if cfg.EchKey != "" {
			err = ech.LoadECHKey(cfg.EchKey, tlsConfig)
			if err != nil {
				log.Errorln("External controller tls serve error: %s", err)
				return
			}
		}
		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		}
		tlsServer = server
		if err = server.Serve(tls.NewListener(l, tlsConfig)); err != nil {
			log.Errorln("External controller tls serve error: %s", err)
		}
	}
}

func startUnix(cfg *Config) {
	// first stop existing server
	if unixServer != nil {
		_ = unixServer.Close()
		unixServer = nil
	}

	// handle addr
	if len(cfg.UnixAddr) > 0 {
		addr := C.Path.Resolve(cfg.UnixAddr)

		dir := filepath.Dir(addr)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Errorln("External controller unix listen error: %s", err)
				return
			}
		}

		// https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
		//
		// Note: As mentioned above in the ‘security’ section, when a socket binds a socket to a valid pathname address,
		// a socket file is created within the filesystem. On Linux, the application is expected to unlink
		// (see the notes section in the man page for AF_UNIX) before any other socket can be bound to the same address.
		// The same applies to Windows unix sockets, except that, DeleteFile (or any other file delete API)
		// should be used to delete the socket file prior to calling bind with the same path.
		_ = syscall.Unlink(addr)

		l, err := inbound.Listen("unix", addr)
		if err != nil {
			log.Errorln("External controller unix listen error: %s", err)
			return
		}
		_ = os.Chmod(addr, 0o666)
		log.Infoln("RESTful API unix listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		unixServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller unix serve error: %s", err)
		}
	}
}

func startPipe(cfg *Config) {
	// first stop existing server
	if pipeServer != nil {
		_ = pipeServer.Close()
		pipeServer = nil
	}

	// handle addr
	if len(cfg.PipeAddr) > 0 {
		if !strings.HasPrefix(cfg.PipeAddr, "\\\\.\\pipe\\") { // windows namedpipe must start with "\\.\pipe\"
			log.Errorln("External controller pipe listen error: windows namedpipe must start with \"\\\\.\\pipe\\\"")
			return
		}

		l, err := inbound.ListenNamedPipe(cfg.PipeAddr)
		if err != nil {
			log.Errorln("External controller pipe listen error: %s", err)
			return
		}
		log.Infoln("RESTful API pipe listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		pipeServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller pipe serve error: %s", err)
		}
	}
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	for range tick.C {
		buf.Reset()
		up, down := t.Now()
		upTotal, downTotal := t.Total()
		if err := json.NewEncoder(buf).Encode(Traffic{
			Up:        up,
			Down:      down,
			UpTotal:   upTotal,
			DownTotal: downTotal,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

// IPStat IP 流量统计
type IPStat struct {
	IP          string `json:"ip"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Connections int    `json:"connections"`
}

// IPStatsResponse IP 统计响应
type IPStatsResponse struct {
	IPStats []IPStat `json:"ipStats"`
}

// trafficIPStats 获取 IP 流量统计（聚合数据）
func trafficIPStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	render.Status(r, http.StatusOK)

	t := statistic.DefaultManager

	// 聚合当前活跃连接的 IP 流量
	ipMap := make(map[string]*IPStat)

	t.Range(func(c statistic.Tracker) bool {
		info := c.Info()
		if info == nil || info.Metadata == nil {
			return true
		}

		ip := info.Metadata.SrcIP.String()
		if ip == "" || ip == "<nil>" {
			return true
		}

		if _, exists := ipMap[ip]; !exists {
			ipMap[ip] = &IPStat{
				IP:          ip,
				Upload:      0,
				Download:    0,
				Connections: 0,
			}
		}

		ipMap[ip].Upload += info.UploadTotal.Load()
		ipMap[ip].Download += info.DownloadTotal.Load()
		ipMap[ip].Connections++

		return true
	})

	// 转换为切片并排序
	ipStats := make([]IPStat, 0, len(ipMap))
	for _, stat := range ipMap {
		ipStats = append(ipStats, *stat)
	}

	// 按总流量排序
	sort.Slice(ipStats, func(i, j int) bool {
		return (ipStats[i].Upload + ipStats[i].Download) >
			(ipStats[j].Upload + ipStats[j].Download)
	})

	// 限制返回数量（最多 100 个 IP）
	if len(ipStats) > 100 {
		ipStats = ipStats[:100]
	}

	json.NewEncoder(w).Encode(IPStatsResponse{
		IPStats: ipStats,
	})
}

// trafficLatest 获取最新流量数据（非流式）
func trafficLatest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	render.Status(r, http.StatusOK)

	t := statistic.DefaultManager
	up, down := t.Now()
	upTotal, downTotal := t.Total()

	json.NewEncoder(w).Encode(Traffic{
		Up:        up,
		Down:      down,
		UpTotal:   upTotal,
		DownTotal: downTotal,
	})
}

func memory(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	first := true
	for range tick.C {
		buf.Reset()

		inuse := t.Memory()
		// make chat.js begin with zero
		// this is shit var,but we need output 0 for first time
		if first {
			inuse = 0
			first = false
		}
		if err := json.NewEncoder(buf).Encode(Memory{
			Inuse:   inuse,
			OSLimit: 0,
		}); err != nil {
			break
		}
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

// TrafficSummary 聚合流量统计响应
type TrafficSummary struct {
	UpTotal   int64    `json:"upTotal"`
	DownTotal int64    `json:"downTotal"`
	IPStats   []IPStat `json:"ipStats"`
}

// trafficSummary 获取聚合流量统计（推荐接口）
func trafficSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	render.Status(r, http.StatusOK)

	t := statistic.DefaultManager

	// 获取全局总量
	upTotal, downTotal := t.Total()

	// 聚合所有 IP 的流量统计（活跃 + 已关闭）
	ipMap := make(map[string]*IPStat)

	// 1. 聚合活跃连接
	t.Range(func(c statistic.Tracker) bool {
		info := c.Info()
		if info == nil || info.Metadata == nil {
			return true
		}

		ip := info.Metadata.SrcIP.String()
		if ip == "" || ip == "<nil>" {
			return true
		}

		if _, exists := ipMap[ip]; !exists {
			ipMap[ip] = &IPStat{
				IP:       ip,
				Upload:   0,
				Download: 0,
			}
		}

		ipMap[ip].Upload += info.UploadTotal.Load()
		ipMap[ip].Download += info.DownloadTotal.Load()

		return true
	})

	// 2. 聚合已关闭连接
	closedConns := t.GetClosedConnections()
	for _, conn := range closedConns {
		ip := conn.SourceIP
		if ip == "" || ip == "invalid IP" {
			continue
		}

		if _, exists := ipMap[ip]; !exists {
			ipMap[ip] = &IPStat{
				IP:       ip,
				Upload:   0,
				Download: 0,
			}
		}

		ipMap[ip].Upload += conn.Upload
		ipMap[ip].Download += conn.Download
	}

	// 3. 转换为切片并排序
	ipStats := make([]IPStat, 0, len(ipMap))
	for _, stat := range ipMap {
		ipStats = append(ipStats, *stat)
	}

	// 按总流量排序
	sort.Slice(ipStats, func(i, j int) bool {
		return (ipStats[i].Upload + ipStats[i].Download) >
			(ipStats[j].Upload + ipStats[j].Download)
	})

	// 4. 返回聚合数据
	json.NewEncoder(w).Encode(TrafficSummary{
		UpTotal:   upTotal,
		DownTotal: downTotal,
		IPStats:   ipStats,
	})
}

// ClosedConnectionsResponse 关闭连接响应
type ClosedConnectionsResponse struct {
	ClosedConnections []statistic.ClosedConnection `json:"closedConnections"`
}

// closedConnections 获取最近关闭的连接
func closedConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	render.Status(r, http.StatusOK)

	closedConns := statistic.DefaultManager.GetClosedConnections()

	json.NewEncoder(w).Encode(ClosedConnectionsResponse{
		ClosedConnections: closedConns,
	})
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type AccumulatedIPStat struct {
	IP          string    `json:"ip"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	FirstSeen   time.Time `json:"firstSeen"`
	FirstSeenTs int64     `json:"firstSeenTimestamp"`
	LastSeen    time.Time `json:"lastSeen"`
	LastSeenTs  int64     `json:"lastSeenTimestamp"`
	ConnCount   int       `json:"connCount"`
}

type AccumulatedResponse struct {
	IPStats        []*AccumulatedIPStat `json:"ipStats"`
	Total          int                  `json:"total"`
	QueryTimestamp int64                `json:"queryTimestamp"`
}

func ipAccumulatedStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	render.Status(r, http.StatusOK)

	if !statistic.DefaultAccumulator.IsEnabled() {
		json.NewEncoder(w).Encode(AccumulatedResponse{
			IPStats:        []*AccumulatedIPStat{},
			Total:          0,
			QueryTimestamp: time.Now().Unix(),
		})
		return
	}

	// 获取已关闭连接的累计流量
	stats, _ := statistic.DefaultAccumulator.GetAllStats()

	// 创建 IP 统计映射
	ipMap := make(map[string]*AccumulatedIPStat)

	// 1. 添加已关闭连接的数据
	for _, stat := range stats {
		ipMap[stat.IP] = &AccumulatedIPStat{
			IP:          stat.IP,
			Upload:      stat.Upload,
			Download:    stat.Download,
			FirstSeen:   stat.FirstSeen,
			FirstSeenTs: stat.FirstSeenTs,
			LastSeen:    stat.LastSeen,
			LastSeenTs:  stat.LastSeenTs,
			ConnCount:   stat.ConnCount,
		}
	}

	// 2. 添加活跃连接的实时流量
	t := statistic.DefaultManager
	t.Range(func(c statistic.Tracker) bool {
		info := c.Info()
		if info == nil || info.Metadata == nil {
			return true
		}

		ip := info.Metadata.SrcIP.String()
		if ip == "" || ip == "<nil>" {
			return true
		}

		if _, exists := ipMap[ip]; !exists {
			now := time.Now()
			ipMap[ip] = &AccumulatedIPStat{
				IP:          ip,
				FirstSeen:   now,
				FirstSeenTs: now.Unix(),
			}
		}

		ipMap[ip].Upload += info.UploadTotal.Load()
		ipMap[ip].Download += info.DownloadTotal.Load()
		ipMap[ip].ConnCount++
		now := time.Now()
		ipMap[ip].LastSeen = now
		ipMap[ip].LastSeenTs = now.Unix()

		return true
	})

	// 转换为切片
	ipStats := make([]*AccumulatedIPStat, 0, len(ipMap))
	for _, stat := range ipMap {
		ipStats = append(ipStats, stat)
	}

	// 按总流量排序
	sort.Slice(ipStats, func(i, j int) bool {
		return (ipStats[i].Upload + ipStats[i].Download) >
			(ipStats[j].Upload + ipStats[j].Download)
	})

	json.NewEncoder(w).Encode(AccumulatedResponse{
		IPStats:        ipStats,
		Total:          len(ipStats),
		QueryTimestamp: time.Now().Unix(),
	})
}

type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for logM := range sub {
			select {
			case ch <- logM:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"meta": C.Meta, "version": C.Version})
}

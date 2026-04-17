package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
		closedConns:   make([]ClosedConnection, 0, 100),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections   xsync.Map[string, Tracker]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	pid           int32
	memory        uint64

	// 关闭连接列表（最近 30 秒）
	closedConns []ClosedConnection
	closedMu    sync.RWMutex
}

// ClosedConnection 关闭的连接信息
type ClosedConnection struct {
	ID       string    `json:"id"`
	SourceIP string    `json:"sourceIP"`
	DestIP   string    `json:"destinationIP"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	ClosedAt time.Time `json:"closedAt"`
}

// 限制关闭连接数量，防止内存泄漏
const maxClosedConns = 3000

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

// RecordClosedConnection 记录关闭的连接
func (m *Manager) RecordClosedConnection(conn ClosedConnection) {
	m.closedMu.Lock()
	defer m.closedMu.Unlock()

	conn.ClosedAt = time.Now()
	m.closedConns = append(m.closedConns, conn)

	// 限制数量，防止内存泄漏（保留最近 1000 个）
	if len(m.closedConns) > maxClosedConns {
		m.closedConns = m.closedConns[len(m.closedConns)-maxClosedConns:]
	}
}

// GetClosedConnections 获取最近关闭的连接
// 注意：返回的是切片引用，调用方不应修改返回的数据
func (m *Manager) GetClosedConnections() []ClosedConnection {
	m.closedMu.RLock()
	defer m.closedMu.RUnlock()

	// 直接返回引用，避免复制开销
	// 调用方应该只读，不要修改
	return m.closedConns
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)
	cleanupTicker := time.NewTicker(60 * time.Second) // 每 60 秒清理一次过期数据
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			m.uploadBlip.Store(m.uploadTemp.Swap(0))
			m.downloadBlip.Store(m.downloadTemp.Swap(0))
		case <-cleanupTicker.C:
			m.cleanupClosedConnections() // 定期清理过期数据
		}
	}
}

// cleanupClosedConnections 清理超过 60 秒的关闭连接
func (m *Manager) cleanupClosedConnections() {
	m.closedMu.Lock()
	defer m.closedMu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	idx := 0
	for i, c := range m.closedConns {
		if c.ClosedAt.After(cutoff) {
			idx = i
			break
		}
	}
	if idx > 0 {
		m.closedConns = m.closedConns[idx:]
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}

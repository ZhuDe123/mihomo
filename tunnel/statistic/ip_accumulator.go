package statistic

import (
	"sync"
	"time"
)

type IPStats struct {
	IP          string    `json:"ip"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	FirstSeen   time.Time `json:"firstSeen"`
	FirstSeenTs int64     `json:"firstSeenTimestamp"`
	LastSeen    time.Time `json:"lastSeen"`
	LastSeenTs  int64     `json:"lastSeenTimestamp"`
	ConnCount   int       `json:"connCount"`
	lastUpdated time.Time `json:"-"`
}

type IPAccumulator struct {
	mu         sync.RWMutex
	stats      map[string]*IPStats
	startTime  time.Time
	enabled    bool
	updateTask *time.Ticker
}

var DefaultAccumulator *IPAccumulator

func init() {
	DefaultAccumulator = &IPAccumulator{
		stats:     make(map[string]*IPStats),
		startTime: time.Now(),
	}
}

func (a *IPAccumulator) Init(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.enabled = enabled

	if enabled {
		a.stats = make(map[string]*IPStats)
		a.startTime = time.Now()
	}
}

func (a *IPAccumulator) StartBatchUpdate() {
	if !a.enabled {
		return
	}

	a.updateTask = time.NewTicker(5 * time.Second)

	go func() {
		defer a.updateTask.Stop()

		for range a.updateTask.C {
			a.batchUpdateLastSeen()
		}
	}()
}

func (a *IPAccumulator) batchUpdateLastSeen() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	for _, stat := range a.stats {
		if now.Sub(stat.lastUpdated) > time.Second {
			stat.LastSeen = now
			stat.LastSeenTs = now.Unix()
			stat.lastUpdated = now
		}
	}
}

func (a *IPAccumulator) AddIPStats(ip string, upload, download int64) {
	if !a.enabled || ip == "" || ip == "<nil>" || ip == "invalid IP" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	if _, exists := a.stats[ip]; !exists {
		a.stats[ip] = &IPStats{
			IP:          ip,
			Upload:      0,
			Download:    0,
			FirstSeen:   now,
			FirstSeenTs: now.Unix(),
			LastSeen:    now,
			LastSeenTs:  now.Unix(),
			ConnCount:   0,
			lastUpdated: now,
		}
	}

	stat := a.stats[ip]
	stat.Upload += upload
	stat.Download += download
	stat.ConnCount++
	stat.LastSeen = now
	stat.LastSeenTs = now.Unix()
	stat.lastUpdated = now
}

func (a *IPAccumulator) GetAllStats() ([]*IPStats, time.Time) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*IPStats, 0, len(a.stats))
	for _, stat := range a.stats {
		result = append(result, stat)
	}

	return result, a.startTime
}

func (a *IPAccumulator) IsEnabled() bool {
	return a.enabled
}

func (a *IPAccumulator) Close() {
	if a.updateTask != nil {
		a.updateTask.Stop()
	}
}

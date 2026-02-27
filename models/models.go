package models

import (
	"encoding/json"
	"time"
)

type ProcessInfo struct {
	PID          int       `json:"pid" db:"pid"`
	PPID         int       `json:"ppid" db:"ppid"`
	Name         string    `json:"name" db:"name"`
	CmdLine      string    `json:"cmdline" db:"cmdline"`
	ExePath      string    `json:"exe_path" db:"exe_path"`
	CWD          string    `json:"cwd" db:"cwd"`
	User         string    `json:"user" db:"user"`
	CPU          float64   `json:"cpu_percent" db:"cpu_percent"`
	Memory       float64   `json:"memory_percent" db:"memory_percent"`
	MemoryRSS    uint64    `json:"memory_rss" db:"memory_rss"`
	MemoryVMS    uint64    `json:"memory_vms" db:"memory_vms"`
	IOReadBytes  uint64    `json:"io_read_bytes" db:"io_read_bytes"`
	IOWriteBytes uint64    `json:"io_write_bytes" db:"io_write_bytes"`
	IOReadRate   uint64    `json:"io_read_rate" db:"io_read_rate"`
	IOWriteRate  uint64    `json:"io_write_rate" db:"io_write_rate"`
	NumThreads   int32     `json:"num_threads" db:"num_threads"`
	NumFDs       int32     `json:"num_fds" db:"num_fds"`
	NumConns     int       `json:"num_connections" db:"num_connections"`
	Status       string    `json:"status" db:"status"`
	CreateTime   int64     `json:"create_time" db:"create_time"`
	Timestamp    time.Time `json:"timestamp" db:"timestamp"`
	IsMonitored  bool      `json:"is_monitored" db:"is_monitored"`
}

type NetworkConnection struct {
	ID         int64     `json:"id" db:"id"`
	PID        int       `json:"pid" db:"pid"`
	Proto      string    `json:"protocol" db:"protocol"`
	LocalIP    string    `json:"local_ip" db:"local_ip"`
	LocalPort  int       `json:"local_port" db:"local_port"`
	RemoteIP   string    `json:"remote_ip" db:"remote_ip"`
	RemotePort int       `json:"remote_port" db:"remote_port"`
	State      string    `json:"state" db:"state"`
	Inode      string    `json:"inode" db:"inode"`
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`
}

type FileEvent struct {
	ID          int64     `json:"id" db:"id"`
	PID         int       `json:"pid" db:"pid"`
	ProcessName string    `json:"process_name" db:"process_name"`
	Operation   string    `json:"operation" db:"operation"`
	Path        string    `json:"path" db:"path"`
	Size        int64     `json:"size" db:"size"`
	Hash        string    `json:"hash" db:"hash"`
	Timestamp   time.Time `json:"timestamp" db:"timestamp"`
}

type MemoryDump struct {
	ID          int64     `json:"id" db:"id"`
	PID         int       `json:"pid" db:"pid"`
	ProcessName string    `json:"process_name" db:"process_name"`
	StartAddr   uint64    `json:"start_addr" db:"start_addr"`
	EndAddr     uint64    `json:"end_addr" db:"end_addr"`
	Size        uint64    `json:"size" db:"size"`
	FilePath    string    `json:"file_path" db:"file_path"`
	Timestamp   time.Time `json:"timestamp" db:"timestamp"`
}

type ProcessEvent struct {
	ID        int64     `json:"id" db:"id"`
	PID       int       `json:"pid" db:"pid"`
	PPID      int       `json:"ppid" db:"ppid"`
	Name      string    `json:"name" db:"name"`
	CmdLine   string    `json:"cmdline" db:"cmdline"`
	EventType string    `json:"event_type" db:"event_type"`
	Timestamp time.Time `json:"timestamp" db:"timestamp"`
}

type SystemStats struct {
	ID          int64     `json:"id" db:"id"`
	CPU         float64   `json:"cpu_percent" db:"cpu_percent"`
	Memory      float64   `json:"memory_percent" db:"memory_percent"`
	MemoryUsed  uint64    `json:"memory_used" db:"memory_used"`
	MemoryTotal uint64    `json:"memory_total" db:"memory_total"`
	DiskUsed    uint64    `json:"disk_used" db:"disk_used"`
	DiskTotal   uint64    `json:"disk_total" db:"disk_total"`
	DiskPercent float64   `json:"disk_percent" db:"disk_percent"`
	NetSent     uint64    `json:"net_sent" db:"net_sent"`
	NetRecv     uint64    `json:"net_recv" db:"net_recv"`
	NetSentRate uint64    `json:"net_sent_rate" db:"net_sent_rate"`
	NetRecvRate uint64    `json:"net_recv_rate" db:"net_recv_rate"`
	LoadAvg1    float64   `json:"load_avg_1" db:"load_avg_1"`
	LoadAvg5    float64   `json:"load_avg_5" db:"load_avg_5"`
	LoadAvg15   float64   `json:"load_avg_15" db:"load_avg_15"`
	Timestamp   time.Time `json:"timestamp" db:"timestamp"`
}

type OpenFile struct {
	ID        int64     `json:"id" db:"id"`
	PID       int       `json:"pid" db:"pid"`
	FD        int       `json:"fd" db:"fd"`
	Path      string    `json:"path" db:"path"`
	Type      string    `json:"type" db:"type"`
	Timestamp time.Time `json:"timestamp" db:"timestamp"`
}

type Module struct {
	ID        int64     `json:"id" db:"id"`
	PID       int       `json:"pid" db:"pid"`
	Name      string    `json:"name" db:"name"`
	Path      string    `json:"path" db:"path"`
	Size      uint64    `json:"size" db:"size"`
	Timestamp time.Time `json:"timestamp" db:"timestamp"`
}

type Alert struct {
	ID           int64     `json:"id" db:"id"`
	PID          int       `json:"pid" db:"pid"`
	ProcessName  string    `json:"process_name" db:"process_name"`
	AlertType    string    `json:"alert_type" db:"alert_type"`
	Severity     string    `json:"severity" db:"severity"`
	Message      string    `json:"message" db:"message"`
	Details      string    `json:"details" db:"details"`
	Timestamp    time.Time `json:"timestamp" db:"timestamp"`
	Acknowledged bool      `json:"acknowledged" db:"acknowledged"`
}

func ToJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

type ProcessTreeNode struct {
	PID      int                `json:"pid"`
	Name     string             `json:"name"`
	CPU      float64            `json:"cpu"`
	Memory   float64            `json:"memory"`
	Children []*ProcessTreeNode `json:"children"`
}

type SearchCriteria struct {
	PID         int
	Name        string
	CPUAbove    float64
	MemoryAbove float64
	HasNetwork  bool
	HasFiles    bool
	TimeRange   struct {
		Start time.Time
		End   time.Time
	}
}

type ExportConfig struct {
	PID           int
	StartTime     time.Time
	EndTime       time.Time
	IncludeNet    bool
	IncludeFiles  bool
	IncludeMemory bool
	IncludeEvents bool
}

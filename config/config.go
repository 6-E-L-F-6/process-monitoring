package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Database   DatabaseConfig   `json:"database"`
	Monitoring MonitoringConfig `json:"monitoring"`
	Logging    LoggingConfig    `json:"logging"`
	Alerts     AlertsConfig     `json:"alerts"`
	Security   SecurityConfig   `json:"security"`
	UI         UIConfig         `json:"ui"`
}

type DatabaseConfig struct {
	Path           string        `json:"path"`
	MaxSize        int64         `json:"max_size_mb"`
	RetentionDays  int           `json:"retention_days"`
	BackupEnabled  bool          `json:"backup_enabled"`
	BackupInterval time.Duration `json:"backup_interval"`
}

type MonitoringConfig struct {
	ProcessInterval   time.Duration `json:"process_interval"`
	SystemInterval    time.Duration `json:"system_interval"`
	FileInterval      time.Duration `json:"file_interval"`
	AnalysisInterval  time.Duration `json:"analysis_interval"`
	TrackAllProcesses bool          `json:"track_all_processes"`
	TrackNetwork      bool          `json:"track_network"`
	TrackFiles        bool          `json:"track_files"`
	TrackMemory       bool          `json:"track_memory"`
}

type LoggingConfig struct {
	Directory     string `json:"directory"`
	Level         string `json:"level"`
	MaxSize       int    `json:"max_size_mb"`
	MaxBackups    int    `json:"max_backups"`
	MaxAge        int    `json:"max_age_days"`
	Compress      bool   `json:"compress"`
	ConsoleOutput bool   `json:"console_output"`
}

type AlertsConfig struct {
	Enabled          bool     `json:"enabled"`
	MinSeverity      string   `json:"min_severity"`
	CPUThreshold     float64  `json:"cpu_threshold"`
	MemoryThreshold  float64  `json:"memory_threshold"`
	IOThreshold      uint64   `json:"io_threshold"`
	NetworkThreshold int      `json:"network_threshold"`
	SuspiciousNames  []string `json:"suspicious_names"`
	Whitelist        []string `json:"whitelist"`
}

type SecurityConfig struct {
	EnableYARA         bool    `json:"enable_yara"`
	YARARulesPath      string  `json:"yara_rules_path"`
	EnableHeuristics   bool    `json:"enable_heuristics"`
	HeuristicThreshold float64 `json:"heuristic_threshold"`
	AutoKillSuspicious bool    `json:"auto_kill_suspicious"`
	MemoryDumpOnAlert  bool    `json:"memory_dump_on_alert"`
}

type UIConfig struct {
	RefreshRate      time.Duration `json:"refresh_rate"`
	ShowAllProcesses bool          `json:"show_all_processes"`
	DefaultSortBy    string        `json:"default_sort_by"`
	ColorScheme      string        `json:"color_scheme"`
	ShowToolbar      bool          `json:"show_toolbar"`
	ShowStatusBar    bool          `json:"show_status_bar"`
}

func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Path:           "./data/procmon.db",
			MaxSize:        1024,
			RetentionDays:  7,
			BackupEnabled:  true,
			BackupInterval: 24 * time.Hour,
		},
		Monitoring: MonitoringConfig{
			ProcessInterval:   1 * time.Second,
			SystemInterval:    5 * time.Second,
			FileInterval:      2 * time.Second,
			AnalysisInterval:  10 * time.Second,
			TrackAllProcesses: true,
			TrackNetwork:      true,
			TrackFiles:        true,
			TrackMemory:       true,
		},
		Logging: LoggingConfig{
			Directory:     "./logs",
			Level:         "info",
			MaxSize:       100,
			MaxBackups:    5,
			MaxAge:        30,
			Compress:      true,
			ConsoleOutput: true,
		},
		Alerts: AlertsConfig{
			Enabled:          true,
			MinSeverity:      "low",
			CPUThreshold:     80.0,
			MemoryThreshold:  50.0,
			IOThreshold:      100 * 1024 * 1024,
			NetworkThreshold: 50,
			SuspiciousNames: []string{
				"miner", "mining", "xmr", "monero",
				"backdoor", "rootkit", "keylogger",
				"trojan", "malware", "virus",
			},
			Whitelist: []string{},
		},
		Security: SecurityConfig{
			EnableYARA:         false,
			YARARulesPath:      "./rules",
			EnableHeuristics:   true,
			HeuristicThreshold: 0.7,
			AutoKillSuspicious: false,
			MemoryDumpOnAlert:  true,
		},
		UI: UIConfig{
			RefreshRate:      1 * time.Second,
			ShowAllProcesses: true,
			DefaultSortBy:    "cpu",
			ColorScheme:      "default",
			ShowToolbar:      true,
			ShowStatusBar:    true,
		},
	}
}

func Load(path string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (c *Config) Validate() error {
	return nil
}

func GetConfigPath() string {
	paths := []string{
		"./config.json",
		"~/.config/procmon/config.json",
		"/etc/procmon/config.json",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return paths[0]
}

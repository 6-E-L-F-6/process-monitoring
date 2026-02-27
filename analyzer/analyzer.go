package analyzer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/utils"
)

type Analyzer struct {
	db         *database.DB
	alertChan  chan *models.Alert
	rules      []DetectionRule
	mu         sync.RWMutex
	baseline   map[int]*ProcessBaseline
	suspicious map[int]bool
}

type ProcessBaseline struct {
	PID         int
	Name        string
	AvgCPU      float64
	AvgMemory   float64
	AvgIORead   uint64
	AvgIOWrite  uint64
	CommonFiles map[string]bool
	CommonConns map[string]bool
	SampleCount int
	LastUpdated time.Time
}

type DetectionRule struct {
	Name        string
	Description string
	Severity    string
	Check       func(*models.ProcessInfo, *ProcessBaseline) (bool, string)
}

func New(db *database.DB) *Analyzer {
	a := &Analyzer{
		db:         db,
		alertChan:  make(chan *models.Alert, 100),
		baseline:   make(map[int]*ProcessBaseline),
		suspicious: make(map[int]bool),
	}

	a.setupRules()
	return a
}

func (a *Analyzer) SetAlertChannel(ch chan *models.Alert) {
	a.alertChan = ch
}

func (a *Analyzer) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.analyzeProcesses()
		}
	}
}

func (a *Analyzer) setupRules() {
	a.rules = []DetectionRule{
		{
			Name:        "High CPU Usage",
			Description: "Process consuming excessive CPU",
			Severity:    "medium",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				if info.CPU > 80 {
					return true, fmt.Sprintf("CPU usage %.1f%% exceeds threshold", info.CPU)
				}
				if baseline != nil && baseline.AvgCPU > 0 {
					if info.CPU > baseline.AvgCPU*5 {
						return true, fmt.Sprintf("CPU usage %.1f%% is %.1fx above baseline", info.CPU, info.CPU/baseline.AvgCPU)
					}
				}
				return false, ""
			},
		},
		{
			Name:        "High Memory Usage",
			Description: "Process consuming excessive memory",
			Severity:    "medium",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				if info.Memory > 50 {
					return true, fmt.Sprintf("Memory usage %.1f%% exceeds threshold", info.Memory)
				}
				return false, ""
			},
		},
		{
			Name:        "Suspicious Process Name",
			Description: "Process name matches known suspicious patterns",
			Severity:    "high",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				suspiciousNames := []string{
					"miner", "mining", "xmr", "monero",
					"backdoor", "rootkit", "keylogger",
					"trojan", "malware", "virus",
					"exploit", "payload", "shell",
				}
				lowerName := strings.ToLower(info.Name)
				for _, pattern := range suspiciousNames {
					if strings.Contains(lowerName, pattern) {
						return true, fmt.Sprintf("Process name contains suspicious pattern: %s", pattern)
					}
				}
				return false, ""
			},
		},
		{
			Name:        "Network Activity Anomaly",
			Description: "Unusual network activity detected",
			Severity:    "high",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				if info.NumConns > 50 {
					return true, fmt.Sprintf("Process has %d network connections", info.NumConns)
				}
				return false, ""
			},
		},
		{
			Name:        "High I/O Activity",
			Description: "Process performing excessive I/O operations",
			Severity:    "low",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				threshold := uint64(100 * 1024 * 1024)
				if info.IOReadRate > threshold || info.IOWriteRate > threshold {
					return true, fmt.Sprintf("High I/O: Read %s/s, Write %s/s",
						utils.HumanBytes(info.IOReadRate), utils.HumanBytes(info.IOWriteRate))
				}
				return false, ""
			},
		},
		{
			Name:        "Hidden Process",
			Description: "Process may be attempting to hide",
			Severity:    "high",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				if info.Name == "" || info.Name == " " {
					return true, "Process has empty or whitespace name"
				}
				if strings.Contains(info.CmdLine, "\\x") {
					return true, "Command line contains encoded characters"
				}
				return false, ""
			},
		},
		{
			Name:        "Privilege Escalation",
			Description: "Process running with elevated privileges",
			Severity:    "medium",
			Check: func(info *models.ProcessInfo, baseline *ProcessBaseline) (bool, string) {
				if info.User == "root" && strings.Contains(info.CmdLine, "sudo") {
					return true, "Process using sudo escalation"
				}
				return false, ""
			},
		},
	}
}

func (a *Analyzer) analyzeProcesses() {
	processes, err := a.db.GetProcesses(100, 0)
	if err != nil {
		return
	}

	for _, proc := range processes {
		a.analyzeProcess(proc)
		a.updateBaseline(proc)
	}
}

func (a *Analyzer) analyzeProcess(info *models.ProcessInfo) {
	a.mu.RLock()
	baseline := a.baseline[info.PID]
	a.mu.RUnlock()

	for _, rule := range a.rules {
		triggered, details := rule.Check(info, baseline)
		if triggered {
			a.triggerAlert(info, rule, details)
		}
	}
}

func (a *Analyzer) triggerAlert(info *models.ProcessInfo, rule DetectionRule, details string) {
	alert := &models.Alert{
		PID:          info.PID,
		ProcessName:  info.Name,
		AlertType:    rule.Name,
		Severity:     rule.Severity,
		Message:      rule.Description,
		Details:      details,
		Timestamp:    time.Now(),
		Acknowledged: false,
	}

	go a.db.SaveAlert(alert)

	select {
	case a.alertChan <- alert:
	default:
	}

	a.mu.Lock()
	a.suspicious[info.PID] = true
	a.mu.Unlock()
}

func (a *Analyzer) updateBaseline(info *models.ProcessInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()

	baseline, exists := a.baseline[info.PID]
	if !exists {
		baseline = &ProcessBaseline{
			PID:         info.PID,
			Name:        info.Name,
			CommonFiles: make(map[string]bool),
			CommonConns: make(map[string]bool),
		}
		a.baseline[info.PID] = baseline
	}

	n := float64(baseline.SampleCount)
	baseline.AvgCPU = (baseline.AvgCPU*n + info.CPU) / (n + 1)
	baseline.AvgMemory = (baseline.AvgMemory*n + info.Memory) / (n + 1)
	baseline.AvgIORead = (baseline.AvgIORead*uint64(n) + info.IOReadRate) / (uint64(n) + 1)
	baseline.AvgIOWrite = (baseline.AvgIOWrite*uint64(n) + info.IOWriteRate) / (uint64(n) + 1)
	baseline.SampleCount++
	baseline.LastUpdated = time.Now()
}

func (a *Analyzer) GetSuspiciousProcesses() []int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var pids []int
	for pid := range a.suspicious {
		pids = append(pids, pid)
	}
	return pids
}

func (a *Analyzer) IsSuspicious(pid int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.suspicious[pid]
}

func (a *Analyzer) ClearSuspicious(pid int) {
	a.mu.Lock()
	delete(a.suspicious, pid)
	a.mu.Unlock()
}

func (a *Analyzer) GetBaseline(pid int) *ProcessBaseline {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.baseline[pid]
}

type YaraScanner struct {
	enabled bool
	rules   []string
}

func NewYaraScanner() *YaraScanner {
	return &YaraScanner{
		enabled: false,
		rules:   []string{},
	}
}

func (ys *YaraScanner) ScanProcess(pid int) ([]string, error) {
	if !ys.enabled {
		return nil, fmt.Errorf("YARA scanner not enabled")
	}
	return []string{}, nil
}

type HeuristicAnalyzer struct {
	db *database.DB
}

func NewHeuristicAnalyzer(db *database.DB) *HeuristicAnalyzer {
	return &HeuristicAnalyzer{db: db}
}

func (ha *HeuristicAnalyzer) Analyze(pid int) (*HeuristicResult, error) {
	result := &HeuristicResult{
		PID:       pid,
		Timestamp: time.Now(),
		Scores:    make(map[string]float64),
	}

	history, err := ha.db.GetProcessHistory(pid, time.Now().Add(-1*time.Hour), time.Now())
	if err != nil {
		return nil, err
	}

	if len(history) == 0 {
		return result, nil
	}

	result.Scores["cpu_variance"] = ha.calculateCPUVariance(history)
	result.Scores["memory_growth"] = ha.calculateMemoryGrowth(history)
	result.Scores["io_anomaly"] = ha.calculateIOAnomaly(history)
	result.Scores["network_anomaly"] = ha.calculateNetworkAnomaly(history)

	var totalScore float64
	for _, score := range result.Scores {
		totalScore += score
	}
	result.ThreatScore = totalScore / float64(len(result.Scores))

	return result, nil
}

func (ha *HeuristicAnalyzer) calculateCPUVariance(history []*models.ProcessInfo) float64 {
	if len(history) < 2 {
		return 0
	}

	var sum, sumSq float64
	for _, h := range history {
		sum += h.CPU
		sumSq += h.CPU * h.CPU
	}

	n := float64(len(history))
	mean := sum / n
	variance := (sumSq / n) - (mean * mean)

	if variance > 1000 {
		return 1.0
	}
	return variance / 1000.0
}

func (ha *HeuristicAnalyzer) calculateMemoryGrowth(history []*models.ProcessInfo) float64 {
	if len(history) < 2 {
		return 0
	}

	first := history[0].Memory
	last := history[len(history)-1].Memory

	if first == 0 {
		return 0
	}

	growth := (last - first) / first
	if growth < 0 {
		return 0
	}
	if growth > 1 {
		return 1
	}
	return growth
}

func (ha *HeuristicAnalyzer) calculateIOAnomaly(history []*models.ProcessInfo) float64 {
	var maxRate uint64
	for _, h := range history {
		if h.IOReadRate > maxRate {
			maxRate = h.IOReadRate
		}
		if h.IOWriteRate > maxRate {
			maxRate = h.IOWriteRate
		}
	}

	threshold := uint64(100 * 1024 * 1024)
	if maxRate > threshold {
		return 1.0
	}
	return float64(maxRate) / float64(threshold)
}

func (ha *HeuristicAnalyzer) calculateNetworkAnomaly(history []*models.ProcessInfo) float64 {
	maxConns := 0
	for _, h := range history {
		if h.NumConns > maxConns {
			maxConns = h.NumConns
		}
	}

	if maxConns > 50 {
		return 1.0
	}
	return float64(maxConns) / 50.0
}

type HeuristicResult struct {
	PID         int
	Timestamp   time.Time
	ThreatScore float64
	Scores      map[string]float64
}

func (hr *HeuristicResult) IsThreat() bool {
	return hr.ThreatScore > 0.7
}

func (hr *HeuristicResult) String() string {
	threatLevel := "LOW"
	if hr.ThreatScore > 0.7 {
		threatLevel = "HIGH"
	} else if hr.ThreatScore > 0.4 {
		threatLevel = "MEDIUM"
	}

	return fmt.Sprintf("Threat Score: %.2f (%s)", hr.ThreatScore, threatLevel)
}

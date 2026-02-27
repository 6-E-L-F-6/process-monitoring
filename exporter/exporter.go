package exporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/models"
)

type Exporter struct {
	db *database.DB
}

func New(db *database.DB) *Exporter {
	return &Exporter{db: db}
}

func (e *Exporter) ExportProcess(pid int, outputPath string) error {
	process, err := e.db.GetProcessByPID(pid)
	if err != nil {
		return fmt.Errorf("failed to get process: %w", err)
	}

	data := map[string]interface{}{
		"process": process,
	}

	conns, _ := e.db.GetNetworkConnectionsByPID(pid)
	if len(conns) > 0 {
		data["network_connections"] = conns
	}

	files, _ := e.db.GetFileEventsByPID(pid, 100)
	if len(files) > 0 {
		data["file_events"] = files
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportProcessHistory(pid int, startTime, endTime time.Time, outputPath string) error {
	history, err := e.db.GetProcessHistory(pid, startTime, endTime)
	if err != nil {
		return fmt.Errorf("failed to get process history: %w", err)
	}

	data := map[string]interface{}{
		"pid":     pid,
		"start":   startTime.Format(time.RFC3339),
		"end":     endTime.Format(time.RFC3339),
		"history": history,
		"count":   len(history),
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportAllProcesses(outputPath string, limit int) error {
	processes, err := e.db.GetProcesses(limit, 0)
	if err != nil {
		return fmt.Errorf("failed to get processes: %w", err)
	}

	data := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"processes": processes,
		"count":     len(processes),
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportNetworkConnections(pid int, outputPath string) error {
	conns, err := e.db.GetNetworkConnectionsByPID(pid)
	if err != nil {
		return fmt.Errorf("failed to get connections: %w", err)
	}

	data := map[string]interface{}{
		"pid":         pid,
		"timestamp":   time.Now().Format(time.RFC3339),
		"connections": conns,
		"count":       len(conns),
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportFileEvents(pid int, outputPath string) error {
	events, err := e.db.GetFileEventsByPID(pid, 1000)
	if err != nil {
		return fmt.Errorf("failed to get file events: %w", err)
	}

	data := map[string]interface{}{
		"pid":       pid,
		"timestamp": time.Now().Format(time.RFC3339),
		"events":    events,
		"count":     len(events),
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportAlerts(outputPath string, includeAcknowledged bool) error {
	alerts, err := e.db.GetAlerts(false, "", 1000)
	if err != nil {
		return fmt.Errorf("failed to get alerts: %w", err)
	}

	if includeAcknowledged {
		ackAlerts, _ := e.db.GetAlerts(true, "", 1000)
		alerts = append(alerts, ackAlerts...)
	}

	data := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"alerts":    alerts,
		"count":     len(alerts),
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportSystemStats(outputPath string) error {
	stats, err := e.db.GetLatestSystemStats()
	if err != nil {
		return fmt.Errorf("failed to get system stats: %w", err)
	}

	data := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"stats":     stats,
	}

	return e.writeJSON(data, outputPath)
}

func (e *Exporter) ExportFullReport(config *models.ExportConfig, outputPath string) error {
	report := &FullReport{
		GeneratedAt: time.Now().Format(time.RFC3339),
		PID:         config.PID,
		StartTime:   config.StartTime.Format(time.RFC3339),
		EndTime:     config.EndTime.Format(time.RFC3339),
	}

	if config.PID != 0 {
		process, err := e.db.GetProcessByPID(config.PID)
		if err == nil {
			report.Process = process
		}

		history, err := e.db.GetProcessHistory(config.PID, config.StartTime, config.EndTime)
		if err == nil {
			report.History = history
		}

		if config.IncludeNet {
			conns, err := e.db.GetNetworkConnectionsByPID(config.PID)
			if err == nil {
				report.NetworkConnections = conns
			}
		}

		if config.IncludeFiles {
			events, err := e.db.GetFileEventsByPID(config.PID, 1000)
			if err == nil {
				report.FileEvents = events
			}
		}
	}

	stats, err := e.db.GetLatestSystemStats()
	if err == nil {
		report.SystemStats = stats
	}

	alerts, err := e.db.GetAlerts(false, "", 100)
	if err == nil {
		report.Alerts = alerts
	}

	return e.writeJSON(report, outputPath)
}

type FullReport struct {
	GeneratedAt        string                      `json:"generated_at"`
	PID                int                         `json:"pid"`
	StartTime          string                      `json:"start_time"`
	EndTime            string                      `json:"end_time"`
	Process            *models.ProcessInfo         `json:"process,omitempty"`
	History            []*models.ProcessInfo       `json:"history,omitempty"`
	NetworkConnections []*models.NetworkConnection `json:"network_connections,omitempty"`
	FileEvents         []*models.FileEvent         `json:"file_events,omitempty"`
	SystemStats        *models.SystemStats         `json:"system_stats,omitempty"`
	Alerts             []*models.Alert             `json:"alerts,omitempty"`
}

func (e *Exporter) writeJSON(data interface{}, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func (e *Exporter) ExportToStdout(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func GetExportFilename(prefix string, pid int) string {
	timestamp := time.Now().Format("20060102_150405")
	if pid > 0 {
		return fmt.Sprintf("%s_%d_%s.json", prefix, pid, timestamp)
	}
	return fmt.Sprintf("%s_%s.json", prefix, timestamp)
}

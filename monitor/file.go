package monitor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/utils"
)

type FileMonitor struct {
	db      *database.DB
	mu      sync.RWMutex
	watched map[int]bool
	events  chan *models.FileEvent
	onEvent func(*models.FileEvent)
}

func NewFileMonitor(db *database.DB) *FileMonitor {
	return &FileMonitor{
		db:      db,
		watched: make(map[int]bool),
		events:  make(chan *models.FileEvent, 1000),
	}
}

func (fm *FileMonitor) SetCallback(onEvent func(*models.FileEvent)) {
	fm.onEvent = onEvent
}

func (fm *FileMonitor) Start(ctx context.Context, interval time.Duration) {
	go fm.processEvents(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fm.scanWatchedProcesses()
		}
	}
}

func (fm *FileMonitor) WatchProcess(pid int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.watched[pid] = true
}

func (fm *FileMonitor) UnwatchProcess(pid int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	delete(fm.watched, pid)
}

func (fm *FileMonitor) scanWatchedProcesses() {
	fm.mu.RLock()
	pids := make([]int, 0, len(fm.watched))
	for pid := range fm.watched {
		pids = append(pids, pid)
	}
	fm.mu.RUnlock()

	for _, pid := range pids {
		fm.scanProcessFiles(pid)
	}
}

func (fm *FileMonitor) scanProcessFiles(pid int) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return
	}

	procName := utils.GetProcessName(pid)

	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}

		if fm.isSystemPath(link) {
			continue
		}

		op := "open"
		if info, err := os.Stat(link); err == nil {
			if info.Mode()&0200 != 0 {
				op = "write"
			}
		}

		event := &models.FileEvent{
			PID:         pid,
			ProcessName: procName,
			Operation:   op,
			Path:        link,
			Timestamp:   time.Now(),
		}

		if info, err := os.Stat(link); err == nil {
			event.Size = info.Size()
		}

		select {
		case fm.events <- event:
		default:
		}
	}
}

func (fm *FileMonitor) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-fm.events:
			go fm.db.SaveFileEvent(event)

			if fm.onEvent != nil {
				go fm.onEvent(event)
			}
		}
	}
}

func (fm *FileMonitor) isSystemPath(path string) bool {
	systemPaths := []string{
		"/dev/",
		"/proc/",
		"/sys/",
		"/run/",
		"/var/run/",
		"pipe:[",
		"socket:[",
		"anon_inode:[",
	}

	for _, prefix := range systemPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) GetProcessFileActivity(pid int) ([]*models.FileEvent, error) {
	return fm.db.GetFileEventsByPID(pid, 100)
}

func (fm *FileMonitor) MonitorSensitivePaths(paths []string) {
	for _, path := range paths {
		go fm.monitorPath(path)
	}
}

func (fm *FileMonitor) monitorPath(path string) {
	if _, err := os.Stat(path); err == nil {
		event := &models.FileEvent{
			PID:         0,
			ProcessName: "system",
			Operation:   "monitor",
			Path:        path,
			Timestamp:   time.Now(),
		}
		fm.db.SaveFileEvent(event)
	}
}

func ParseProcFdInfo(pid int, fd string) map[string]string {
	info := make(map[string]string)
	path := fmt.Sprintf("/proc/%d/fdinfo/%s", pid, fd)

	file, err := os.Open(path)
	if err != nil {
		return info
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			info[key] = value
		}
	}

	return info
}

func GetFilePosition(pid int, fd string) int64 {
	info := ParseProcFdInfo(pid, fd)
	if pos, ok := info["pos"]; ok {
		posInt, _ := strconv.ParseInt(pos, 10, 64)
		return posInt
	}
	return 0
}

func GetFileFlags(pid int, fd string) string {
	info := ParseProcFdInfo(pid, fd)
	if flags, ok := info["flags"]; ok {
		return flags
	}
	return ""
}

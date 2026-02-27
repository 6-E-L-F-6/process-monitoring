package logger

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/utils"
)

type Logger struct {
	db        *database.DB
	logDir    string
	logFile   *os.File
	logChan   chan *models.ProcessInfo
	eventChan chan *models.ProcessEvent
	alertChan chan *models.Alert
	mu        sync.Mutex
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

func New(db *database.DB, logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logFile := filepath.Join(logDir, fmt.Sprintf("procmon_%s.log", time.Now().Format("20060102")))
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &Logger{
		db:        db,
		logDir:    logDir,
		logFile:   file,
		logChan:   make(chan *models.ProcessInfo, 1000),
		eventChan: make(chan *models.ProcessEvent, 100),
		alertChan: make(chan *models.Alert, 100),
		stopChan:  make(chan struct{}),
	}

	return logger, nil
}

func (l *Logger) Start(ctx context.Context) {
	l.wg.Add(3)
	go l.processLogs(ctx)
	go l.processEvents(ctx)
	go l.processAlerts(ctx)
}

func (l *Logger) Stop() {
	close(l.stopChan)
	l.wg.Wait()

	l.mu.Lock()
	if l.logFile != nil {
		l.logFile.Close()
	}
	l.mu.Unlock()
}

func (l *Logger) LogProcess(info *models.ProcessInfo) {
	select {
	case l.logChan <- info:
	default:
	}
}

func (l *Logger) LogEvent(event *models.ProcessEvent) {
	select {
	case l.eventChan <- event:
	default:
	}
}

func (l *Logger) LogAlert(alert *models.Alert) {
	select {
	case l.alertChan <- alert:
	default:
	}
}

func (l *Logger) processLogs(ctx context.Context) {
	defer l.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var batch []*models.ProcessInfo

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopChan:
			return
		case info := <-l.logChan:
			batch = append(batch, info)
			if len(batch) >= 100 {
				l.saveBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				l.saveBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (l *Logger) saveBatch(batch []*models.ProcessInfo) {
	for _, info := range batch {
		go l.db.SaveProcess(info)

		l.mu.Lock()
		if l.logFile != nil {
			logLine := fmt.Sprintf("[%s] PID=%d NAME=%s CPU=%.2f%% MEM=%.2f%% IO_R=%s IO_W=%s\n",
				info.Timestamp.Format("2006-01-02 15:04:05"),
				info.PID,
				info.Name,
				info.CPU,
				info.Memory,
				utils.HumanBytes(info.IOReadBytes),
				utils.HumanBytes(info.IOWriteBytes),
			)
			l.logFile.WriteString(logLine)
		}
		l.mu.Unlock()
	}
}

func (l *Logger) processEvents(ctx context.Context) {
	defer l.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopChan:
			return
		case event := <-l.eventChan:
			go l.db.SaveProcessEvent(event)

			l.mu.Lock()
			if l.logFile != nil {
				logLine := fmt.Sprintf("[%s] EVENT=%s PID=%d NAME=%s\n",
					event.Timestamp.Format("2006-01-02 15:04:05"),
					event.EventType,
					event.PID,
					event.Name,
				)
				l.logFile.WriteString(logLine)
			}
			l.mu.Unlock()
		}
	}
}

func (l *Logger) processAlerts(ctx context.Context) {
	defer l.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopChan:
			return
		case alert := <-l.alertChan:
			go l.db.SaveAlert(alert)

			l.mu.Lock()
			if l.logFile != nil {
				logLine := fmt.Sprintf("[%s] ALERT=%s SEVERITY=%s PID=%d MESSAGE=%s\n",
					alert.Timestamp.Format("2006-01-02 15:04:05"),
					alert.AlertType,
					alert.Severity,
					alert.PID,
					alert.Message,
				)
				l.logFile.WriteString(logLine)
			}
			l.mu.Unlock()
		}
	}
}

func (l *Logger) RotateLog() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logFile != nil {
		l.logFile.Close()
	}

	newLogFile := filepath.Join(l.logDir, fmt.Sprintf("procmon_%s.log", time.Now().Format("20060102")))
	file, err := os.OpenFile(newLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	l.logFile = file
	return nil
}

func (l *Logger) GetLogFile() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logFile.Name()
}

func LogToConsole(format string, args ...interface{}) {
	log.Printf(format, args...)
}

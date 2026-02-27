package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/analyzer"
	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/exporter"
	"github.com/6-E-L-F-6/process-monitoring/logger"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/monitor"
	"github.com/6-E-L-F-6/process-monitoring/ui"
)

const (
	version = "2.0.0"
	appName = "Process Monitor"
	author  = "E | L F"
)

func main() {
	var (
		dbPath      = flag.String("db", "./data/procmon.db", "Database file path")
		logDir      = flag.String("log", "./logs", "Log directory")
		dumpDir     = flag.String("dump", "./dumps", "Memory dump directory")
		interval    = flag.Duration("interval", 1*time.Second, "Monitoring interval")
		mode        = flag.String("mode", "monitor", "Mode: monitor, export, or viewer")
		exportPID   = flag.Int("pid", 0, "PID to export (for export mode)")
		exportPath  = flag.String("output", "", "Export output path")
		showVersion = flag.Bool("version", false, "Show version")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s v%s by %s\n", appName, version, author)
		os.Exit(0)
	}

	ensureDir(filepath.Dir(*dbPath))
	ensureDir(*logDir)
	ensureDir(*dumpDir)

	db, err := database.New(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		cancel()
	}()

	switch *mode {
	case "monitor":
		runMonitor(ctx, db, *logDir, *dumpDir, *interval)
	case "export":
		runExport(db, *exportPID, *exportPath)
	case "viewer":
		runLogViewer()
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

func runMonitor(ctx context.Context, db *database.DB, logDir, dumpDir string, interval time.Duration) {
	log, err := logger.New(db, logDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Stop()
	log.Start(ctx)

	procMon := monitor.NewProcessMonitor(db)
	sysMon := monitor.NewSystemMonitor(db)
	fileMon := monitor.NewFileMonitor(db)
	memDumper, err := monitor.NewMemoryDumper(db, dumpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create memory dumper: %v\n", err)
		os.Exit(1)
	}

	procMon.SetCallbacks(
		func(info *models.ProcessInfo) {
			log.LogEvent(&models.ProcessEvent{
				PID:       info.PID,
				PPID:      info.PPID,
				Name:      info.Name,
				CmdLine:   info.CmdLine,
				EventType: "start",
				Timestamp: time.Now(),
			})
		},
		func(pid int) {
			log.LogEvent(&models.ProcessEvent{
				PID:       pid,
				EventType: "exit",
				Timestamp: time.Now(),
			})
		},
	)

	fileMon.SetCallback(func(event *models.FileEvent) {
	})

	anlz := analyzer.New(db)
	go anlz.Start(ctx, interval*10)

	go procMon.Start(ctx, interval)
	go sysMon.Start(ctx, interval*5)
	go fileMon.Start(ctx, interval*2)

	ui := ui.New(db, procMon, sysMon, fileMon, memDumper)
	if err := ui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "UI error: %v\n", err)
		os.Exit(1)
	}
}

func runExport(db *database.DB, pid int, outputPath string) {
	exp := exporter.New(db)

	if pid == 0 {
		fmt.Println("Exporting all processes...")
		if outputPath == "" {
			outputPath = exporter.GetExportFilename("all_processes", 0)
		}
		if err := exp.ExportAllProcesses(outputPath, 1000); err != nil {
			fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Exporting process %d...\n", pid)
		if outputPath == "" {
			outputPath = exporter.GetExportFilename("process", pid)
		}
		if err := exp.ExportProcess(pid, outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Exported to: %s\n", outputPath)
}

func runLogViewer() {
	fmt.Println("Log viewer mode - not implemented in this version")
	fmt.Println("Use SQLite browser to view the database directly")
}

func ensureDir(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directory %s: %v\n", path, err)
		os.Exit(1)
	}
}

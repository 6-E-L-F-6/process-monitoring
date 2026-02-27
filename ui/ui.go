package ui

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/exporter"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/monitor"
	"github.com/6-E-L-F-6/process-monitoring/utils"
)

type UI struct {
	app       *tview.Application
	db        *database.DB
	procMon   *monitor.ProcessMonitor
	sysMon    *monitor.SystemMonitor
	fileMon   *monitor.FileMonitor
	memDumper *monitor.MemoryDumper
	exp       *exporter.Exporter

	pages         *tview.Pages
	mainFlex      *tview.Flex
	procTable     *tview.Table
	detailView    *tview.TextView
	logView       *tview.TextView
	statusBar     *tview.TextView
	searchBox     *tview.InputField
	lockIndicator *tview.TextView

	selectedPID int
	lockedPID   int
	searchQuery string
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	processList []*models.ProcessInfo
}

func New(db *database.DB, procMon *monitor.ProcessMonitor, sysMon *monitor.SystemMonitor,
	fileMon *monitor.FileMonitor, memDumper *monitor.MemoryDumper) *UI {

	ctx, cancel := context.WithCancel(context.Background())

	return &UI{
		app:       tview.NewApplication(),
		db:        db,
		procMon:   procMon,
		sysMon:    sysMon,
		fileMon:   fileMon,
		memDumper: memDumper,
		exp:       exporter.New(db),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (ui *UI) Run() error {
	ui.setupUI()
	ui.setupKeyBindings()
	ui.startRefreshLoop()

	return ui.app.Run()
}

func (ui *UI) Stop() {
	ui.cancel()
	ui.app.Stop()
}

func (ui *UI) setupUI() {
	ui.pages = tview.NewPages()

	ui.mainFlex = tview.NewFlex()

	leftPanel := ui.createLeftPanel()

	rightPanel := ui.createRightPanel()

	ui.statusBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)

	ui.mainFlex.
		AddItem(leftPanel, 0, 2, true).
		AddItem(rightPanel, 0, 1, false)

	mainWithStatus := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.mainFlex, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)

	ui.pages.AddPage("main", mainWithStatus, true, true)
	ui.app.SetRoot(ui.pages, true).EnableMouse(true)
	ui.updateStatusBar()
}

func (ui *UI) createLeftPanel() tview.Primitive {
	ui.lockIndicator = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	ui.updateLockIndicator()

	ui.searchBox = tview.NewInputField().
		SetLabel("Search: ").
		SetFieldWidth(40)

	ui.procTable = tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSelectionChangedFunc(func(row, col int) {
			ui.onProcessSelected(row)
		})
	ui.procTable.SetBorder(true).SetTitle(" Processes ")

	ui.setTableHeaders()

	ui.logView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			ui.logView.ScrollToEnd()
		})
	ui.logView.SetBorder(true).SetTitle(" Event Log ")

	leftFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.lockIndicator, 1, 0, false).
		AddItem(ui.searchBox, 1, 0, false).
		AddItem(ui.procTable, 0, 3, true).
		AddItem(ui.logView, 8, 0, false)

	return leftFlex
}

func (ui *UI) setTableHeaders() {
	headers := []string{"PID", "PPID", "Name", "CPU%", "Mem%", "IO R", "IO W", "Net", "Status"}
	for i, h := range headers {
		cell := tview.NewTableCell(fmt.Sprintf("[::b]%s", h)).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false).
			SetAlign(tview.AlignLeft)
		ui.procTable.SetCell(0, i, cell)
	}
}

func (ui *UI) createRightPanel() tview.Primitive {
	ui.detailView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	ui.detailView.SetBorder(true).SetTitle(" Process Details ")
	ui.detailView.SetText("[gray]Select a process to view details[-]")

	return ui.detailView
}

func (ui *UI) setupKeyBindings() {
	ui.searchBox.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEnter:
			ui.searchQuery = strings.ToLower(strings.TrimSpace(ui.searchBox.GetText()))
			ui.refreshProcessTable()
			ui.app.SetFocus(ui.procTable)
		case tcell.KeyEscape:
			ui.searchBox.SetText("")
			ui.searchQuery = ""
			ui.refreshProcessTable()
			ui.app.SetFocus(ui.procTable)
		case tcell.KeyTab:
			ui.app.SetFocus(ui.procTable)
		}
	})

	ui.procTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			ui.lockProcess()
			return nil
		case tcell.KeyEsc:
			ui.unlockProcess()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				ui.Stop()
				return nil
			case 'r':
				ui.refreshProcessTable()
				return nil
			case 'd':
				ui.dumpMemory()
				return nil
			case 'e':
				ui.exportProcess()
				return nil
			case 'l':
				ui.toggleLogProcess()
				return nil
			case 'a':
				ui.showAlerts()
				return nil
			case 'h', '?':
				ui.showHelp()
				return nil
			case 'k':
				ui.killProcess()
				return nil
			case '/':
				ui.app.SetFocus(ui.searchBox)
				return nil
			}
		case tcell.KeyCtrlC:
			ui.Stop()
			return nil
		case tcell.KeyCtrlR:
			ui.refreshProcessTable()
			return nil
		case tcell.KeyCtrlD:
			ui.dumpMemory()
			return nil
		case tcell.KeyCtrlE:
			ui.exportProcess()
			return nil
		case tcell.KeyCtrlL:
			ui.toggleLogProcess()
			return nil
		case tcell.KeyCtrlA:
			ui.showAlerts()
			return nil
		case tcell.KeyCtrlH:
			ui.showHelp()
			return nil
		case tcell.KeyCtrlQ:
			ui.Stop()
			return nil
		case tcell.KeyTab:
			ui.app.SetFocus(ui.searchBox)
			return nil
		}
		return event
	})

	ui.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return event
	})
}

func (ui *UI) startRefreshLoop() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ui.ctx.Done():
				return
			case <-ticker.C:
				ui.app.QueueUpdateDraw(func() {
					ui.refreshProcessTable()
					ui.refreshDetails()
					ui.updateStatusBar()
				})
			}
		}
	}()
}

func (ui *UI) refreshProcessTable() {
	row, _ := ui.procTable.GetSelection()
	var currentPID int
	if row > 0 && row < ui.procTable.GetRowCount() {
		cell := ui.procTable.GetCell(row, 0)
		if cell != nil {
			currentPID, _ = strconv.Atoi(cell.Text)
		}
	}

	ui.procTable.Clear()
	ui.setTableHeaders()

	var processes []*models.ProcessInfo
	var err error

	if ui.searchQuery != "" {
		processes, err = ui.db.SearchProcesses(ui.searchQuery, 0, 0, 0)
	} else {
		processes, err = ui.db.GetTopProcessesByCPU(100)
	}

	if err != nil {
		return
	}

	ui.mu.Lock()
	ui.processList = processes
	ui.mu.Unlock()

	newSelectionRow := -1
	for i, p := range processes {
		if i >= 100 {
			break
		}

		row := i + 1

		if p.PID == currentPID {
			newSelectionRow = row
		}

		cpuColor := tcell.ColorGreen
		if p.CPU > 50 {
			cpuColor = tcell.ColorRed
		} else if p.CPU > 20 {
			cpuColor = tcell.ColorOrange
		}

		memColor := tcell.ColorGreen
		if p.Memory > 50 {
			memColor = tcell.ColorRed
		} else if p.Memory > 20 {
			memColor = tcell.ColorOrange
		}

		statusColor := tcell.ColorGreen
		if p.Status != "running" && p.Status != "sleeping" {
			statusColor = tcell.ColorYellow
		}

		ui.procTable.SetCell(row, 0, tview.NewTableCell(strconv.Itoa(p.PID)).SetTextColor(tcell.ColorWhite))
		ui.procTable.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(p.PPID)).SetTextColor(tcell.ColorGray))
		ui.procTable.SetCell(row, 2, tview.NewTableCell(utils.TruncateString(p.Name, 20)).SetTextColor(tcell.ColorLightBlue))
		ui.procTable.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%.1f", p.CPU)).SetTextColor(cpuColor))
		ui.procTable.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%.1f", p.Memory)).SetTextColor(memColor))
		ui.procTable.SetCell(row, 5, tview.NewTableCell(utils.HumanBytes(p.IOReadRate)).SetTextColor(tcell.ColorGray))
		ui.procTable.SetCell(row, 6, tview.NewTableCell(utils.HumanBytes(p.IOWriteRate)).SetTextColor(tcell.ColorGray))
		ui.procTable.SetCell(row, 7, tview.NewTableCell(strconv.Itoa(p.NumConns)).SetTextColor(tcell.ColorGreen))
		ui.procTable.SetCell(row, 8, tview.NewTableCell(p.Status).SetTextColor(statusColor))
	}

	if newSelectionRow > 0 {
		ui.procTable.Select(newSelectionRow, 0)
	} else if row > 0 && row < ui.procTable.GetRowCount() {
		ui.procTable.Select(row, 0)
	} else if ui.procTable.GetRowCount() > 1 {
		ui.procTable.Select(1, 0)
	}
}

func (ui *UI) onProcessSelected(row int) {
	if row <= 0 {
		ui.selectedPID = 0
		return
	}

	cell := ui.procTable.GetCell(row, 0)
	if cell == nil {
		ui.selectedPID = 0
		return
	}

	pid, err := strconv.Atoi(cell.Text)
	if err != nil {
		ui.selectedPID = 0
		return
	}

	ui.selectedPID = pid
	ui.refreshDetails()
}

func (ui *UI) refreshDetails() {
	pid := ui.selectedPID
	if ui.lockedPID != 0 {
		pid = ui.lockedPID
	}

	if pid == 0 {
		return
	}

	process, err := ui.db.GetProcessByPID(pid)
	if err != nil {
		ui.detailView.SetText(fmt.Sprintf("[red]Error: %v[-]", err))
		return
	}

	var b strings.Builder

	lockStatus := ""
	if ui.lockedPID == pid {
		lockStatus = " [red][LOCKED][-]"
	}
	fmt.Fprintf(&b, "[::b][yellow]=== Process %d%s ===[-]\n\n", pid, lockStatus)

	fmt.Fprintf(&b, "[cyan]Name:[-] %s\n", process.Name)
	fmt.Fprintf(&b, "[cyan]Command:[-] %s\n", utils.TruncateString(process.CmdLine, 100))
	fmt.Fprintf(&b, "[cyan]Executable:[-] %s\n", process.ExePath)
	fmt.Fprintf(&b, "[cyan]Working Dir:[-] %s\n", process.CWD)
	fmt.Fprintf(&b, "[cyan]User:[-] %s\n", process.User)
	fmt.Fprintf(&b, "[cyan]Status:[-] %s\n", process.Status)
	fmt.Fprintf(&b, "[cyan]Parent PID:[-] %d\n\n", process.PPID)

	fmt.Fprintf(&b, "[::b][yellow]=== Resource Usage ===[-]\n")
	fmt.Fprintf(&b, "[cyan]CPU:[-] %.2f%% %s\n", process.CPU, utils.MakeBar(process.CPU, 20))
	fmt.Fprintf(&b, "[cyan]Memory:[-] %.2f%% %s\n", process.Memory, utils.MakeBar(process.Memory, 20))
	fmt.Fprintf(&b, "[cyan]RSS:[-] %s\n", utils.HumanBytes(process.MemoryRSS))
	fmt.Fprintf(&b, "[cyan]VMS:[-] %s\n", utils.HumanBytes(process.MemoryVMS))
	fmt.Fprintf(&b, "[cyan]Threads:[-] %d\n", process.NumThreads)
	fmt.Fprintf(&b, "[cyan]File Descriptors:[-] %d\n", process.NumFDs)
	fmt.Fprintf(&b, "[cyan]Network Connections:[-] %d\n\n", process.NumConns)

	fmt.Fprintf(&b, "[::b][yellow]=== I/O Statistics ===[-]\n")
	fmt.Fprintf(&b, "[cyan]Read:[-] %s/s (total: %s)\n", utils.HumanBytes(process.IOReadRate), utils.HumanBytes(process.IOReadBytes))
	fmt.Fprintf(&b, "[cyan]Write:[-] %s/s (total: %s)\n\n", utils.HumanBytes(process.IOWriteRate), utils.HumanBytes(process.IOWriteBytes))

	conns, _ := ui.db.GetNetworkConnectionsByPID(pid)
	if len(conns) > 0 {
		fmt.Fprintf(&b, "[::b][yellow]=== Network Connections (%d) ===[-]\n", len(conns))
		for i, conn := range conns {
			if i >= 10 {
				fmt.Fprintf(&b, "  ... and %d more\n", len(conns)-10)
				break
			}
			fmt.Fprintf(&b, "  [green]%s[-] %s:%d -> %s:%d [gray](%s)[-]\n",
				conn.Proto, conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort, conn.State)
		}
		fmt.Fprintln(&b)
	}

	files, _ := ui.procMon.GetOpenFiles(pid)
	if len(files) > 0 {
		fmt.Fprintf(&b, "[::b][yellow]=== Open Files (%d) ===[-]\n", len(files))
		for i, f := range files {
			if i >= 20 {
				fmt.Fprintf(&b, "  ... and %d more\n", len(files)-20)
				break
			}
			fmt.Fprintf(&b, "  [gray]%d:[-] %s\n", f.FD, utils.TruncateString(f.Path, 50))
		}
		fmt.Fprintln(&b)
	}

	maps, _ := ui.memDumper.GetMemoryMaps(pid)
	if len(maps) > 0 {
		fmt.Fprintf(&b, "[::b][yellow]=== Memory Maps (%d regions) ===[-]\n", len(maps))
		for i, m := range maps {
			if i >= 10 {
				fmt.Fprintf(&b, "  ... and %d more\n", len(maps)-10)
				break
			}
			perms := ""
			if m["readable"].(bool) {
				perms += "r"
			} else {
				perms += "-"
			}
			if m["writable"].(bool) {
				perms += "w"
			} else {
				perms += "-"
			}
			if m["executable"].(bool) {
				perms += "x"
			} else {
				perms += "-"
			}
			pathStr := ""
			if path, ok := m["path"].(string); ok {
				pathStr = utils.TruncateString(path, 30)
			}
			fmt.Fprintf(&b, "  [gray]%s[-] %s %s [gray]%s[-]\n",
				m["start"], perms, m["size"], pathStr)
		}
	}

	ui.detailView.SetText(b.String())
}

func (ui *UI) lockProcess() {
	if ui.selectedPID == 0 {
		ui.log("[yellow]No process selected to lock[-]")
		return
	}

	ui.lockedPID = ui.selectedPID
	ui.updateLockIndicator()
	ui.log(fmt.Sprintf("[green]Locked to PID %d[-]", ui.lockedPID))
	ui.refreshDetails()
}

func (ui *UI) unlockProcess() {
	if ui.lockedPID == 0 {
		return
	}

	oldPID := ui.lockedPID
	ui.lockedPID = 0
	ui.updateLockIndicator()
	ui.log(fmt.Sprintf("[yellow]Unlocked from PID %d[-]", oldPID))
	ui.refreshDetails()
}

func (ui *UI) updateLockIndicator() {
	if ui.lockedPID != 0 {
		ui.lockIndicator.SetText(fmt.Sprintf("[red]:: LOCKED TO PID %d ::[-]", ui.lockedPID))
	} else {
		ui.lockIndicator.SetText("[gray]:: Press Enter to lock process ::[-]")
	}
}

func (ui *UI) dumpMemory() {
	pid := ui.selectedPID
	if ui.lockedPID != 0 {
		pid = ui.lockedPID
	}
	if pid == 0 {
		ui.showError("No process selected")
		return
	}

	go func() {
		ui.log(fmt.Sprintf("Dumping memory of PID %d...", pid))
		dumpFile, err := ui.memDumper.DumpProcessMemory(pid)
		if err != nil {
			ui.app.QueueUpdateDraw(func() {
				ui.showError(fmt.Sprintf("Failed to dump memory: %v", err))
			})
			return
		}
		ui.app.QueueUpdateDraw(func() {
			ui.log(fmt.Sprintf("[green]Memory dumped to: %s[-]", dumpFile))
		})
	}()
}

func (ui *UI) exportProcess() {
	pid := ui.selectedPID
	if ui.lockedPID != 0 {
		pid = ui.lockedPID
	}
	if pid == 0 {
		ui.showError("No process selected")
		return
	}

	go func() {
		filename := exporter.GetExportFilename("process", pid)
		outputPath := "/tmp/" + filename
		err := ui.exp.ExportProcess(pid, outputPath)
		if err != nil {
			ui.app.QueueUpdateDraw(func() {
				ui.showError(fmt.Sprintf("Export failed: %v", err))
			})
			return
		}
		ui.app.QueueUpdateDraw(func() {
			ui.log(fmt.Sprintf("[green]Exported to: %s[-]", outputPath))
		})
	}()
}

func (ui *UI) toggleLogProcess() {
	pid := ui.selectedPID
	if ui.lockedPID != 0 {
		pid = ui.lockedPID
	}
	if pid == 0 {
		ui.showError("No process selected")
		return
	}

	ui.fileMon.WatchProcess(pid)
	ui.log(fmt.Sprintf("[green]Now watching PID %d for file activity[-]", pid))
}

func (ui *UI) showAlerts() {
	alerts, err := ui.db.GetAlerts(false, "", 50)
	if err != nil {
		ui.showError(fmt.Sprintf("Failed to get alerts: %v", err))
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[::b][yellow]=== Alerts (%d unacknowledged) ===[-]\n\n", len(alerts))

	for _, alert := range alerts {
		severityColor := "green"
		switch alert.Severity {
		case "high":
			severityColor = "red"
		case "medium":
			severityColor = "orange"
		}

		fmt.Fprintf(&b, "[%s]%s[-] [gray]%s[-] PID=%d %s: %s\n",
			severityColor, alert.Severity,
			alert.Timestamp.Format("15:04:05"),
			alert.PID, alert.AlertType, alert.Message)
	}

	ui.detailView.SetText(b.String())
}

func (ui *UI) showHelp() {
	help := `[::b][yellow]=== Process Monitor Help ===[-]

[::b]Navigation:[-]
  [green]↑/↓[-]     Navigate processes
  [green]Enter[-]   Lock to process (shows [red]LOCKED[-] indicator)
  [green]Esc[-]     Unlock process
  [green]/[-]      Focus search box
  [green]Tab[-]     Switch focus

[::b]Search:[-]
  [green]/[-]      Focus search box
  [green]Enter[-]   Execute search
  [green]Esc[-]     Clear search

[::b]Actions:[-]
  [green]r[-]       Refresh
  [green]d[-]       Dump memory
  [green]e[-]       Export to JSON
  [green]l[-]       Toggle logging
  [green]a[-]       Show alerts
  [green]k[-]       Kill process

[::b]System:[-]
  [green]h/?[-]     Show this help
  [green]q/Ctrl+C[-] Quit

[::b]Shortcuts:[-]
  [green]Ctrl+R[-]  Refresh
  [green]Ctrl+D[-]  Dump memory
  [green]Ctrl+E[-]  Export
  [green]Ctrl+L[-]  Toggle logging
  [green]Ctrl+A[-]  Alerts
  [green]Ctrl+H[-]  Help
  [green]Ctrl+Q[-]  Quit
`
	ui.detailView.SetText(help)
}

func (ui *UI) killProcess() {
	pid := ui.selectedPID
	if ui.lockedPID != 0 {
		pid = ui.lockedPID
	}
	if pid == 0 {
		ui.showError("No process selected")
		return
	}

	modal := tview.NewModal().
		SetText(fmt.Sprintf("Are you sure you want to kill PID %d?", pid)).
		AddButtons([]string{"Yes", "No"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				go func() {
					proc, err := os.FindProcess(pid)
					if err != nil {
						ui.app.QueueUpdateDraw(func() {
							ui.showError(fmt.Sprintf("Failed to find process: %v", err))
						})
						return
					}
					if err := proc.Kill(); err != nil {
						ui.app.QueueUpdateDraw(func() {
							ui.showError(fmt.Sprintf("Failed to kill process: %v", err))
						})
						return
					}
					ui.log(fmt.Sprintf("[green]Killed PID %d[-]", pid))
				}()
			}
			ui.pages.RemovePage("modal")
		})

	ui.pages.AddPage("modal", modal, true, true)
}

func (ui *UI) showError(msg string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("[red]Error:[-] %s", msg)).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ui.pages.RemovePage("modal")
		})
	ui.pages.AddPage("modal", modal, true, true)
}

func (ui *UI) log(msg string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Fprintf(ui.logView, "[gray]%s[-] %s\n", timestamp, msg)
}

func (ui *UI) updateStatusBar() {
	stats, err := ui.db.GetLatestSystemStats()
	if err != nil {
		ui.statusBar.SetText(" [yellow]Loading...[-]")
		return
	}

	status := fmt.Sprintf(
		" CPU: [yellow]%.1f%%[-] | Mem: [yellow]%.1f%%[-] | Disk: [yellow]%.1f%%[-] | Net: [green]↑%s[-] [blue]↓%s[-] | Load: [gray]%.2f %.2f %.2f[-] ",
		stats.CPU, stats.Memory, stats.DiskPercent,
		utils.HumanBytes(stats.NetSentRate), utils.HumanBytes(stats.NetRecvRate),
		stats.LoadAvg1, stats.LoadAvg5, stats.LoadAvg15,
	)
	ui.statusBar.SetText(status)
}

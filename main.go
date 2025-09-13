// Created By E | L F

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	pscpu "github.com/shirou/gopsutil/v3/cpu"
	psdisk "github.com/shirou/gopsutil/v3/disk"
	pshost "github.com/shirou/gopsutil/v3/host"
	psmem "github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	psproc "github.com/shirou/gopsutil/v3/process"
)

type AppState struct {
	mu           sync.Mutex
	lastInfo     map[int]map[string]interface{}
	filteredPids []int
	currentQuery string
	historyMu    sync.Mutex
	cpuHistory   []float64
	memHistory   []float64
	lockedPID    int
	lastIO       map[int]struct {
		read  uint64
		write uint64
	}
}
type ProcNetConn struct {
	Proto     string
	LocalIP   string
	LocalPort string
	RemIP     string
	RemPort   string
	State     string
	Inode     string
}
type ProcessLog struct {
	Time      string        `json:"time"`
	PID       int           `json:"pid"`
	Name      string        `json:"name"`
	Cmd       string        `json:"cmd"`
	CPU       float64       `json:"cpu"`
	Mem       float64       `json:"mem"`
	IORead    uint64        `json:"io_read"`
	IOWrite   uint64        `json:"io_write"`
	OpenFiles []string      `json:"open_files"`
	NetConns  []ProcNetConn `json:"net_conns"`
}
type LogState struct {
	mu           sync.Mutex
	logSpecific  int
	specificFile *os.File
	stopChan     chan struct{}
}
type LogFile struct {
	Name  string
	Lines []string
}
type LogViewerState struct {
	files       []LogFile
	currentFile int
	currentLine int
	mu          sync.Mutex
	active      bool
}

var startLoggingOnce sync.Once
var logChan = make(chan ProcessLog, 1000)

func askFolderAndCreateLog(app *tview.Application, label string, logState *LogState, pid int, state *AppState, mainFlex tview.Primitive) {
	inputField := tview.NewInputField().SetLabel(label).SetFieldWidth(60)
	startButton := tview.NewButton("Start Logging").SetSelectedFunc(func() {
		folder := strings.TrimSpace(inputField.GetText())
		if folder == "" {
			showErrorModal(app, "Folder path cannot be empty", mainFlex)
			return
		}

		go func() {
			if _, err := os.Stat(folder); os.IsNotExist(err) {
				if err := os.MkdirAll(folder, 0755); err != nil {
					app.QueueUpdateDraw(func() {
						showErrorModal(app, "Cannot create folder: "+err.Error(), mainFlex)
					})
					return
				}
			}

			var filename string
			if pid == 0 {
				filename = filepath.Join(folder, "all.log")
			} else {
				filename = filepath.Join(folder, fmt.Sprintf("pid_%d.log", pid))
			}

			file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				app.QueueUpdateDraw(func() {
					showErrorModal(app, "Cannot open log file: "+err.Error(), mainFlex)
				})
				return
			}

			logState.mu.Lock()
			if pid != 0 {
				if logState.specificFile != nil {
					_ = logState.specificFile.Close()
				}
				logState.specificFile = file
				logState.logSpecific = pid
			}
			logState.mu.Unlock()

			startLoggingOnce.Do(func() {
				go startLogging(state, logState)
			})

			app.QueueUpdateDraw(func() {
				app.SetRoot(mainFlex, true).SetFocus(mainFlex)
			})
		}()
	})

	buttonFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(nil, 2, 0, false).
		AddItem(startButton, 20, 0, true).
		AddItem(nil, 0, 1, false)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(inputField, 1, 0, true).
		AddItem(buttonFlex, 1, 0, false)

	app.QueueUpdateDraw(func() {
		app.SetRoot(flex, true).EnableMouse(true)
	})
}
func buildSocketInodeToPidMap() (map[string][]int, error) {
	res := make(map[string][]int)
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return res, err
	}
	for _, e := range procEntries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:") {
				inode := strings.Trim(link[len("socket:"):], "[]")
				res[inode] = append(res[inode], pid)
			}
		}
	}
	return res, nil
}
func buildProcessSnapshot(socketMap map[string]ProcNetConn) ([]*psproc.Process, map[int]map[string]interface{}, error) {
	procs, err := psproc.Processes()
	if err != nil {
		return nil, nil, err
	}
	infoMap := make(map[int]map[string]interface{})
	for _, p := range procs {
		pid := int(p.Pid)
		m := make(map[string]interface{})

		name, _ := p.Name()
		cpu, _ := p.CPUPercent()
		memPercent32, _ := p.MemoryPercent()
		memPercent := float64(memPercent32)
		cmd, _ := p.Cmdline()
		ioR, ioW, _ := getProcIO(pid)

		m["name"] = name
		m["cpu"] = cpu
		m["mem"] = memPercent
		m["cmd"] = cmd
		m["io_read"] = ioR
		m["io_write"] = ioW
		m["open_files"] = nil
		m["net"] = nil

		infoMap[pid] = m
	}
	return procs, infoMap, nil
}
func drawWave(values []float64, height int, width int) string {
	if len(values) == 0 {
		return ""
	}
	v := values
	if len(v) > width {
		v = v[len(v)-width:]
	}
	rows := make([]string, height)
	for r := 0; r < height; r++ {
		rows[r] = strings.Repeat(" ", width)
	}
	for x := 0; x < len(v); x++ {
		val := v[x]
		y := int((val / 100.0) * float64(height-1))
		rowIndex := (height - 1) - y
		row := []rune(rows[rowIndex])
		row[x] = '▇'
		rows[rowIndex] = string(row)
	}
	return strings.Join(rows, "\n")
}
func drawProcessTable(procTable *tview.Table, state *AppState, query string) {
	procTable.Clear()
	headers := []string{"PID", "Name", "CPU%", "Mem%", "IO R", "IO W", "Net"}
	for i, h := range headers {
		procTable.SetCell(0, i, tview.NewTableCell("[::b]"+h).SetTextColor(tcell.ColorWhite).SetSelectable(false))
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	showPids := []int{}
	if query == "" {
		showPids = append([]int{}, state.filteredPids...)
	} else {
		lq := strings.ToLower(query)
		for _, pid := range state.filteredPids {
			if info, ok := state.lastInfo[pid]; ok {
				name := strings.ToLower(fmt.Sprintf("%v", info["name"]))
				cmd := strings.ToLower(fmt.Sprintf("%v", info["cmd"]))
				pidStr := strconv.Itoa(pid)
				if strings.Contains(name, lq) || strings.Contains(cmd, lq) || strings.Contains(pidStr, lq) {
					showPids = append(showPids, pid)
				}
			}
		}
	}

	row := 1
	for _, pid := range showPids {
		if row > 300 {
			break
		}
		info := state.lastInfo[pid]
		name := fmt.Sprintf("%v", info["name"])
		cpuVal := info["cpu"].(float64)
		memVal := info["mem"].(float64)
		ioR := info["io_read"].(uint64)
		ioW := info["io_write"].(uint64)
		netCount := 0
		if nc, ok := info["net"].([]ProcNetConn); ok {
			netCount = len(nc)
		}

		cpuColor := tcell.ColorGreen
		if cpuVal > 50 {
			cpuColor = tcell.ColorRed
		} else if cpuVal > 20 {
			cpuColor = tcell.ColorOrange
		}

		procTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", pid)).SetTextColor(tcell.ColorWhite))
		procTable.SetCell(row, 1, tview.NewTableCell(name).SetTextColor(tcell.ColorLightBlue))
		procTable.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%.2f", cpuVal)).SetTextColor(cpuColor))
		procTable.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%.2f", memVal)).SetTextColor(tcell.ColorAqua))
		procTable.SetCell(row, 4, tview.NewTableCell(humanBytes(ioR)).SetTextColor(tcell.ColorGray))
		procTable.SetCell(row, 5, tview.NewTableCell(humanBytes(ioW)).SetTextColor(tcell.ColorGray))
		procTable.SetCell(row, 6, tview.NewTableCell(fmt.Sprintf("%d", netCount)).SetTextColor(tcell.ColorGreen))
		row++
	}
}
func getSystemSummaryParts() (uptime string, cpuPercent float64, memPercent float64, diskPercent float64, netSummary string, hostInfo string, err error) {
	cpuPercents, err := pscpu.PercentWithContext(context.Background(), 0, false)
	if err != nil {
		return "", 0, 0, 0, "", "", err
	}
	mem, _ := psmem.VirtualMemory()
	disk, _ := psdisk.Usage("/")
	host, _ := pshost.Info()
	netIOs, _ := psnet.IOCounters(false)
	uptime = (time.Duration(host.Uptime) * time.Second).String()
	cpuPercent = cpuPercents[0]
	memPercent = mem.UsedPercent
	diskPercent = disk.UsedPercent
	netSummary = formatNetIO(netIOs)
	hostInfo = fmt.Sprintf("%s %s", host.Platform, host.KernelVersion)
	return
}
func getOpenFiles(pid int) ([]string, error) {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := ioutil.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}
		out = append(out, link)
	}
	sort.Strings(out)
	return out, nil
}
func getProcIO(pid int) (readBytes, writeBytes uint64, err error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "io")
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		if strings.HasPrefix(l, "read_bytes:") {
			parts := strings.Fields(l)
			v, _ := strconv.ParseUint(parts[1], 10, 64)
			readBytes = v
		} else if strings.HasPrefix(l, "write_bytes:") {
			parts := strings.Fields(l)
			v, _ := strconv.ParseUint(parts[1], 10, 64)
			writeBytes = v
		}
	}
	return
}
func formatNetIO(ioCounters []psnet.IOCountersStat) string {
	if len(ioCounters) == 0 {
		return "-"
	}
	i := ioCounters[0]
	return fmt.Sprintf("TX %s / RX %s", humanBytes(i.BytesSent), humanBytes(i.BytesRecv))
}
func newSearchBox() *tview.InputField {
	return tview.NewInputField().SetLabel("Search: ").SetFieldWidth(30)
}
func newProcTable() *tview.Table {
	table := tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0)
	table.SetBorder(true).SetTitle(" Processes ")
	return table
}
func newSummaryBox() *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	tv.SetBorder(true).SetTitle(" System ")
	return tv
}
func newDetailBox() *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)
	tv.SetBorder(true).SetTitle(" Details ")
	return tv
}
func newFooter() *tview.TextView {
	t := tview.NewTextView().SetTextAlign(tview.AlignCenter)
	t.SetText("[Ctrl+C] quit  [Enter] show details [Ctrl+P] log process [Ctrl+K] stop logging")
	return t
}
func humanBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	t := float64(b) / 1024.0
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	i := 0
	for t >= 1024 && i < len(units)-1 {
		t /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", t, units[i])
}
func loadLogsFromFolder(path string) ([]LogFile, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var logFiles []LogFile
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		content, err := ioutil.ReadFile(filepath.Join(path, f.Name()))
		if err != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")
		logFiles = append(logFiles, LogFile{
			Name:  f.Name(),
			Lines: lines,
		})
	}
	return logFiles, nil
}
func parseHexIPPort(hexIPPort string) (ip string, port string, err error) {
	parts := strings.Split(hexIPPort, ":")
	if len(parts) != 2 {
		return "", "", errors.New("invalid hex ip:port")
	}
	h := parts[0]
	phex := parts[1]

	pval, err := strconv.ParseInt(phex, 16, 64)
	if err != nil {
		return "", "", err
	}
	port = fmt.Sprintf("%d", pval)

	switch len(h) {
	case 8:
		b, err1 := hex.DecodeString(h)
		if err1 != nil || len(b) != 4 {
			return "", "", errors.New("decode error")
		}
		ip = fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
		return
	case 32:
		b, err1 := hex.DecodeString(h)
		if err1 != nil || len(b) != 16 {
			return "", "", errors.New("decode error")
		}
		for i := 0; i < 8; i++ {
			b[i], b[15-i] = b[15-i], b[i]
		}
		ip = net.IP(b).String()
		return
	default:
		return "", "", errors.New("unexpected ip hex length")
	}
}
func renderLogEntryJSONColored(logView *tview.TextView, entry string) {
	var logEntry ProcessLog
	if err := json.Unmarshal([]byte(entry), &logEntry); err != nil {
		fmt.Fprintf(logView, "[red]Invalid JSON[-]: %s\n", entry)
		return
	}

	fmt.Fprintf(logView, "[::b][white]=== Log Entry ===[-]\n")

	fmt.Fprintf(logView, "PID:[yellow] %d[-]\n", logEntry.PID)
	fmt.Fprintf(logView, "Time:[green] %s[-]\n", logEntry.Time)
	fmt.Fprintf(logView, "Name:[green] %s[-]\n", logEntry.Name)
	fmt.Fprintf(logView, "Cmd:[green] %s[-]\n\n", logEntry.Cmd)

	cpuColor := "red"
	switch {
	case logEntry.CPU < 50:
		cpuColor = "green"
	case logEntry.CPU < 80:
		cpuColor = "orange"
	}
	fmt.Fprintf(logView, "CPU:[%s] %.2f%%[-]\n", cpuColor, logEntry.CPU)

	memColor := "red"
	switch {
	case logEntry.Mem < 50:
		memColor = "green"
	case logEntry.Mem < 80:
		memColor = "orange"
	}
	fmt.Fprintf(logView, "Mem:[%s] %.2f%%[-]\n", memColor, logEntry.Mem)

	ioReadColor := "green"

	switch {
	case logEntry.IORead > 100*1024*1024:
		ioReadColor = "red"
	case logEntry.IORead > 10*1024*1024:
		ioReadColor = "orange"
	}

	ioWriteColor := "green"
	switch {
	case logEntry.IOWrite > 100*1024*1024:
		ioWriteColor = "red"
	case logEntry.IOWrite > 10*1024*1024:
		ioWriteColor = "orange"
	}

	fmt.Fprintf(logView, "IO Read:[%s] %s[-]\n", ioReadColor, humanBytes(logEntry.IORead))
	fmt.Fprintf(logView, "IO Write:[%s] %s[-]\n\n", ioWriteColor, humanBytes(logEntry.IOWrite))

	if logEntry.OpenFiles != nil && len(logEntry.OpenFiles) > 0 {
		fmt.Fprintf(logView, "[purple]Open Files (%d):[-]\n", len(logEntry.OpenFiles))
		for i, f := range logEntry.OpenFiles {
			fmt.Fprintf(logView, "  %2d. %s\n", i+1, f)
		}
		fmt.Fprintln(logView, "")
	} else {
		fmt.Fprintf(logView, "[purple]Open Files:[-] [gray]N/A[-]\n\n")
	}

	if logEntry.NetConns != nil && len(logEntry.NetConns) > 0 {
		fmt.Fprintf(logView, "[purple]Net Connections (%d):[-]\n", len(logEntry.NetConns))
		fmt.Fprintf(logView, "[white]%-3s %-6s %-21s %-21s %-12s %-8s[-]\n",
			"#", "Proto", "Local", "Remote", "State", "Inode")
		fmt.Fprintf(logView, "[white]----------------------------------------------------------------------------[-]\n")

		for i, conn := range logEntry.NetConns {
			local := fmt.Sprintf("%s:%s", conn.LocalIP, conn.LocalPort)
			remote := fmt.Sprintf("%s:%s", conn.RemIP, conn.RemPort)

			fmt.Fprintf(logView,
				"[cyan]%-3d [green]%-6s [yellow]%-21s [blue]%-21s [orange]%-12s [gray]%-8s[-]\n",
				i+1, conn.Proto, local, remote, conn.State, conn.Inode)
		}
		fmt.Fprintln(logView, "")
	} else {
		fmt.Fprintf(logView, "[purple]Net Connections:[-] [gray]N/A[-]\n")
	}
}
func renderProcessDetails(detailBox *tview.TextView, state *AppState, pid int) {
	state.mu.Lock()
	info, ok := state.lastInfo[pid]
	state.mu.Unlock()
	if !ok {
		detailBox.SetText(fmt.Sprintf("No info for PID %d", pid))
		return
	}

	openFilesIface, ok := info["open_files"]
	var openFiles []string
	if !ok || openFilesIface == nil {
		openFiles, _ = getOpenFiles(pid)
		if openFiles == nil {
			openFiles = []string{}
		}
		info["open_files"] = openFiles
	} else {
		openFiles, ok = openFilesIface.([]string)
		if !ok {
			openFiles = []string{}
		}
	}

	netIface, ok := info["net"]
	var netConns []ProcNetConn
	if !ok || netIface == nil {
		tcpConns, _ := readProcNet("tcp")
		udpConns, _ := readProcNet("udp")
		for k, v := range udpConns {
			tcpConns[k] = v
		}

		fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		if fds, err := ioutil.ReadDir(fdDir); err == nil {
			for _, fd := range fds {
				link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
				if err != nil {
					continue
				}
				if strings.HasPrefix(link, "socket:") {
					inode := strings.Trim(link[len("socket:"):], "[]")
					if c, ok := tcpConns[inode]; ok {
						netConns = append(netConns, c)
					}
				}
			}
		}
		info["net"] = netConns
	} else {
		netConns, ok = netIface.([]ProcNetConn)
		if !ok {
			netConns = []ProcNetConn{}
		}
	}

	state.mu.Lock()
	state.lastInfo[pid] = info
	state.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "[yellow]PID:[white] %d\n", pid)
	fmt.Fprintf(&b, "[yellow]Name:[white] %s\n", info["name"])
	fmt.Fprintf(&b, "[yellow]Cmd:[white] %s\n", info["cmd"])
	fmt.Fprintf(&b, "[yellow]CPU:[white] %.2f%%  [yellow]Mem:[white] %.2f%%\n",
		info["cpu"].(float64), info["mem"].(float64))
	fmt.Fprintf(&b, "[yellow]IO Read:[white] %s  [yellow]IO Write:[white] %s\n",
		humanBytes(info["io_read"].(uint64)), humanBytes(info["io_write"].(uint64)))

	fmt.Fprintf(&b, "\n[yellow]Open files (first 100):[white]\n")
	for i, f := range openFiles {
		if i >= 100 {
			fmt.Fprintf(&b, "  (... %d more)\n", len(openFiles)-100)
			break
		}
		fmt.Fprintf(&b, "  %s\n", f)
	}

	fmt.Fprintf(&b, "\n[yellow]Network connections (%d):[white]\n", len(netConns))
	for _, n := range netConns {
		stateHuman := tcpStateHuman(n.State)
		fmt.Fprintf(&b, "  %s:%s -> %s:%s [%s]\n",
			n.LocalIP, n.LocalPort, n.RemIP, n.RemPort, stateHuman)
	}

	detailBox.SetText(b.String())
}
func readProcNet(proto string) (map[string]ProcNetConn, error) {
	path := "/proc/net/" + proto
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := make(map[string]ProcNetConn)
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		local, rem, state, inode := fields[1], fields[2], fields[3], fields[9]
		lip, lp, err1 := parseHexIPPort(local)
		rip, rp, err2 := parseHexIPPort(rem)
		if err1 != nil || err2 != nil {
			continue
		}
		res[inode] = ProcNetConn{
			Proto:     proto,
			LocalIP:   lip,
			LocalPort: lp,
			RemIP:     rip,
			RemPort:   rp,
			State:     state,
			Inode:     inode,
		}
	}
	return res, nil
}
func updateLoop(app *tview.Application, summaryBox *tview.TextView, procTable *tview.Table, state *AppState) {
	for {
		_, infoMap, _ := buildProcessSnapshot(nil)

		_, cpuP, memP, _, _, _, _ := getSystemSummaryParts()

		state.historyMu.Lock()
		state.cpuHistory = append(state.cpuHistory, cpuP)
		if len(state.cpuHistory) > 60 {
			state.cpuHistory = state.cpuHistory[len(state.cpuHistory)-60:]
		}
		state.memHistory = append(state.memHistory, memP)
		if len(state.memHistory) > 60 {
			state.memHistory = state.memHistory[len(state.memHistory)-60:]
		}
		state.historyMu.Unlock()

		state.mu.Lock()
		state.lastInfo = infoMap
		state.filteredPids = state.filteredPids[:0]
		for pid := range state.lastInfo {
			state.filteredPids = append(state.filteredPids, pid)
		}
		sort.Slice(state.filteredPids, func(i, j int) bool {
			a := state.lastInfo[state.filteredPids[i]]
			b := state.lastInfo[state.filteredPids[j]]
			return a["cpu"].(float64) > b["cpu"].(float64)
		})
		currentQuery := state.currentQuery
		state.mu.Unlock()

		app.QueueUpdateDraw(func() {
			drawProcessTable(procTable, state, currentQuery)
		})

		time.Sleep(700 * time.Millisecond)
	}
}
func updateDetailLoop(app *tview.Application, detailBox *tview.TextView, procTable *tview.Table, state *AppState) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	prevPID := 0
	prevData := ""

	for range ticker.C {
		state.mu.Lock()
		locked := state.lockedPID
		state.mu.Unlock()

		var pid int
		if locked != 0 {
			pid = locked
		} else {
			row, _ := procTable.GetSelection()
			if row > 0 {
				cell := procTable.GetCell(row, 0)
				if cell != nil {
					if p, err := strconv.Atoi(cell.Text); err == nil {
						pid = p
					}
				}
			}
		}

		if pid == 0 {
			app.QueueUpdateDraw(func() {
				detailBox.SetText("No process selected")
			})
			continue
		}

		state.mu.Lock()
		info, ok := state.lastInfo[pid]
		state.mu.Unlock()
		if !ok {
			continue
		}

		data := fmt.Sprintf("%v", info)
		if pid != prevPID || data != prevData {
			prevPID = pid
			prevData = data
			app.QueueUpdateDraw(func() {
				renderProcessDetails(detailBox, state, pid)
			})
		}
	}
}
func startLogging(state *AppState, logState *LogState) {
	logState.mu.Lock()
	if logState.stopChan == nil {
		logState.stopChan = make(chan struct{})
	}
	stopChan := logState.stopChan
	logState.mu.Unlock()

	go func() {
		for {
			select {
			case logEntry := <-logChan:
				data, err := json.Marshal(logEntry)
				if err != nil {
					continue
				}
				data = append(data, '\n')

				logState.mu.Lock()

				if logState.specificFile != nil && logState.logSpecific == logEntry.PID {
					logState.specificFile.Write(data)
				}
				logState.mu.Unlock()
			case <-stopChan:
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				state.mu.Lock()
				if logState.logSpecific == 0 {
					state.mu.Unlock()
					continue
				}
				pids := make([]int, 0, len(state.lastInfo))
				for pid := range state.lastInfo {
					pids = append(pids, pid)
				}
				infoCopy := make(map[int]map[string]interface{})
				for pid, info := range state.lastInfo {
					infoCopy[pid] = info
				}
				state.mu.Unlock()

				for _, pid := range pids {
					info := infoCopy[pid]
					logEntry := ProcessLog{
						Time:    time.Now().Format("2006-01-02 15:04:05"),
						PID:     pid,
						Name:    fmt.Sprintf("%v", info["name"]),
						Cmd:     fmt.Sprintf("%v", info["cmd"]),
						CPU:     info["cpu"].(float64),
						Mem:     info["mem"].(float64),
						IORead:  info["io_read"].(uint64),
						IOWrite: info["io_write"].(uint64),
					}
					if ofsIface, ok := info["open_files"]; ok && ofsIface != nil {
						if ofs, ok := ofsIface.([]string); ok {
							if len(ofs) > 100 {
								logEntry.OpenFiles = append(ofs[:100], fmt.Sprintf("... %d more", len(ofs)-100))
							} else {
								logEntry.OpenFiles = ofs
							}
						}
					}
					if ncIface, ok := info["net"]; ok && ncIface != nil {
						if nc, ok := ncIface.([]ProcNetConn); ok {
							logEntry.NetConns = nc
						}
					}
					select {
					case logChan <- logEntry:
					default:
					}
				}
			case <-stopChan:
				return
			}
		}
	}()
}
func stopLogging(logState *LogState) {
	logState.mu.Lock()
	defer logState.mu.Unlock()

	if logState.stopChan != nil {
		close(logState.stopChan)
		logState.stopChan = nil
	}

	if logState.specificFile != nil {
		logState.specificFile.Sync()
		logState.specificFile.Close()
		logState.specificFile = nil
	}

	logState.logSpecific = 0
}
func showErrorModal(app *tview.Application, msg string, mainFlex tview.Primitive) {
	modal := tview.NewModal().
		SetText(msg).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			app.QueueUpdateDraw(func() {
				app.SetRoot(mainFlex, true).SetFocus(mainFlex)
			})
		})
	app.QueueUpdateDraw(func() {
		app.SetRoot(modal, false).SetFocus(modal)
	})
}
func showProcessDetailsByPID(detailBox *tview.TextView, state *AppState, pid int) {
	renderProcessDetails(detailBox, state, pid)
}
func showProcessDetails(row int, procTable *tview.Table, detailBox *tview.TextView, state *AppState) {
	cell := procTable.GetCell(row, 0)
	if cell == nil {
		detailBox.SetText("No process selected")
		return
	}
	pidStr := strings.TrimSpace(cell.Text)
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		detailBox.SetText("Invalid PID")
		return
	}
	renderProcessDetails(detailBox, state, pid)
}
func setupSearch(searchBox *tview.InputField, procTable *tview.Table, state *AppState, app *tview.Application) {
	var searchTimerMu sync.Mutex
	var searchTimer *time.Timer
	searchBox.SetChangedFunc(func(text string) {
		state.mu.Lock()
		state.currentQuery = strings.TrimSpace(text)
		state.mu.Unlock()

		searchTimerMu.Lock()
		if searchTimer != nil {
			searchTimer.Stop()
		}
		searchTimer = time.AfterFunc(200*time.Millisecond, func() {
			app.QueueUpdateDraw(func() {
				state.mu.Lock()
				query := state.currentQuery
				state.mu.Unlock()
				drawProcessTable(procTable, state, query)
			})
		})
		searchTimerMu.Unlock()
	})
}
func setupInputCapture(app *tview.Application, state *AppState, logState *LogState, procTable *tview.Table, mainFlex tview.Primitive) {
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlC:
			app.Stop()
			return nil
		case tcell.KeyEnter:
			row, _ := procTable.GetSelection()
			if row > 0 {
				cell := procTable.GetCell(row, 0)
				if cell != nil {
					if pid, err := strconv.Atoi(cell.Text); err == nil {
						state.mu.Lock()
						state.lockedPID = pid
						state.mu.Unlock()
					}
				}
			}
			return nil
		case tcell.KeyEsc:
			state.mu.Lock()
			state.lockedPID = 0
			state.mu.Unlock()
			return nil

		case tcell.KeyCtrlP:
			row, _ := procTable.GetSelection()
			if row <= 0 {
				return nil
			}
			cell := procTable.GetCell(row, 0)
			if cell == nil {
				return nil
			}
			pid, err := strconv.Atoi(cell.Text)
			if err != nil {
				return nil
			}
			go askFolderAndCreateLog(app, fmt.Sprintf("Select folder to save PID %d logs: ", pid), logState, pid, state, mainFlex)
			return nil
		case tcell.KeyCtrlK:
			go func() {
				stopLogging(logState)
				app.QueueUpdateDraw(func() {
					modal := tview.NewModal().
						SetText("Process logging stopped").
						AddButtons([]string{"OK"}).
						SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							app.SetRoot(mainFlex, true).SetFocus(mainFlex)
						})
					app.SetRoot(modal, false).SetFocus(modal)
				})
			}()
			return nil

		}
		return event
	})
}
func startMonitoringApp(state *AppState, logState *LogState) {
	app := tview.NewApplication()
	searchBox := newSearchBox()
	procTable := newProcTable()
	summaryBox := newSummaryBox()
	detailBox := newDetailBox()
	footer := newFooter()

	leftFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(searchBox, 1, 0, true).
		AddItem(procTable, 0, 1, true).
		AddItem(footer, 1, 0, false)

	rightFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(detailBox, 0, 1, false)

	mainFlex := tview.NewFlex().
		AddItem(leftFlex, 0, 2, true).
		AddItem(rightFlex, 0, 1, false)

	go startLogging(state, logState)
	go updateLoop(app, summaryBox, procTable, state)
	go updateDetailLoop(app, detailBox, procTable, state)

	setupSearch(searchBox, procTable, state, app)
	setupInputCapture(app, state, logState, procTable, mainFlex)

	if err := app.SetRoot(mainFlex, true).EnableMouse(true).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running app: %v\n", err)
		os.Exit(1)
	}
}
func startLogViewerApp(state *AppState) {
	app := tview.NewApplication()

	pathInput := tview.NewInputField().
		SetLabel("Enter Log Folder Path: ").
		SetFieldWidth(50)

	showError := func(msg string) {
		modal := tview.NewModal().
			SetText(msg).
			AddButtons([]string{"OK"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				app.Stop()
			})
		app.SetRoot(modal, false)
	}

	pathInput.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}

		path := strings.TrimSpace(pathInput.GetText())
		go func() {
			allFiles, err := ioutil.ReadDir(path)
			if err != nil {
				app.QueueUpdateDraw(func() {
					showError("Cannot read folder: " + err.Error())
				})
				return
			}

			var logFiles []LogFile
			for _, f := range allFiles {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".log") {
					continue
				}
				content, err := ioutil.ReadFile(filepath.Join(path, f.Name()))
				if err != nil {
					continue
				}
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				logFiles = append(logFiles, LogFile{Name: f.Name(), Lines: lines})
			}

			if len(logFiles) == 0 {
				app.QueueUpdateDraw(func() {
					showError("No .log files found")
				})
				return
			}

			app.QueueUpdateDraw(func() {
				fileList := tview.NewList().ShowSecondaryText(false)

				logView := tview.NewTextView()
				logView.SetDynamicColors(true).
					SetWrap(true).
					SetBorder(true).
					SetTitle(" Log Viewer ")

				fileList.SetBorder(true).SetTitle(" Log Files ")

				lv := &LogViewerState{
					files:  logFiles,
					active: true,
				}
				lv.currentFile = 0
				lv.currentLine = 0

				updateLogView := func() {
					logView.Clear()
					file := lv.files[lv.currentFile]

					if lv.currentLine < 0 {
						lv.currentLine = 0
					}
					if lv.currentLine >= len(file.Lines) {
						lv.currentLine = len(file.Lines) - 1
					}

					fmt.Fprintf(logView, "[::b]File: %s  (%d/%d lines)\n\n",
						file.Name, lv.currentLine+1, len(file.Lines))
					renderLogEntryJSONColored(logView, file.Lines[lv.currentLine])
				}

				for i, f := range logFiles {
					idx := i
					fileList.AddItem(f.Name, "", 0, func() {
						lv.currentFile = idx
						lv.currentLine = 0
						updateLogView()
					})
				}

				app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
					switch event.Key() {
					case tcell.KeyLeft:
						lv.currentLine--
						if lv.currentLine < 0 {
							lv.currentLine = 0
						}
						updateLogView()
						return nil

					case tcell.KeyRight:
						lv.currentLine++
						if lv.currentLine >= len(lv.files[lv.currentFile].Lines) {
							lv.currentLine = len(lv.files[lv.currentFile].Lines) - 1
						}
						updateLogView()
						return nil

					case tcell.KeyUp:
						lv.currentFile--
						if lv.currentFile < 0 {
							lv.currentFile = 0
						}
						lv.currentLine = 0
						updateLogView()
						return nil

					case tcell.KeyDown:
						lv.currentFile++
						if lv.currentFile >= len(lv.files) {
							lv.currentFile = len(lv.files) - 1
						}
						lv.currentLine = 0
						updateLogView()
						return nil

					case tcell.KeyEsc:
						app.Stop()
						return nil
					}
					return event
				})

				flex := tview.NewFlex().
					AddItem(fileList, 30, 1, true).
					AddItem(logView, 0, 2, false)

				updateLogView()
				app.SetRoot(flex, true).EnableMouse(true)
			})
		}()
	})

	if err := app.SetRoot(pathInput, true).EnableMouse(true).Run(); err != nil {
		fmt.Println("Error running log viewer:", err)
	}
}
func safeStr(s string) string {
	if s == "" {
		return "[gray]N/A[-]"
	}
	return s
}
func tcpStateHuman(s string) string {
	m := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if v, ok := m[s]; ok {
		return v
	}
	return s
}
func makeBar(percent float64, length int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := int(percent / 100.0 * float64(length))
	if filled > length {
		filled = length
	}

	return "[" + strings.Repeat("━", filled) + strings.Repeat("─", length-filled) + "]"
}
func mainMenu(app *tview.Application, state *AppState, logState *LogState) {
	menu := tview.NewList().
		AddItem("Monitoring Mode", "Start live process monitoring", 'm', func() {
			app.Stop()
			startMonitoringApp(state, logState)
		}).
		AddItem("Log Viewer Mode", "View previously saved logs", 'l', func() {
			app.Stop()
			startLogViewerApp(state)
		}).
		AddItem("Quit", "Exit application", 'q', func() {
			app.Stop()
		})
	menu.SetBorder(true).SetTitle("Main Menu")
	if err := app.SetRoot(menu, true).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running menu: %v\n", err)
		os.Exit(1)
	}
}
func main() {

	app := tview.NewApplication()

	state := &AppState{
		lastInfo:     make(map[int]map[string]interface{}),
		filteredPids: []int{},
		cpuHistory:   make([]float64, 0, 60),
		memHistory:   make([]float64, 0, 60),
		lastIO:       make(map[int]struct{ read, write uint64 }),
	}

	logState := &LogState{
		logSpecific: 0,
	}

	mainMenu(app, state, logState)
}

package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	pscpu "github.com/shirou/gopsutil/v3/cpu"
	psdisk "github.com/shirou/gopsutil/v3/disk"
	psload "github.com/shirou/gopsutil/v3/load"
	psmem "github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	psproc "github.com/shirou/gopsutil/v3/process"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/utils"
)

type ProcessMonitor struct {
	db            *database.DB
	mu            sync.RWMutex
	monitored     map[int]bool
	lastIO        map[int]struct{ read, write uint64 }
	lastNet       map[int]struct{ sent, recv uint64 }
	onNewProcess  func(*models.ProcessInfo)
	onProcessExit func(int)
}

func NewProcessMonitor(db *database.DB) *ProcessMonitor {
	return &ProcessMonitor{
		db:        db,
		monitored: make(map[int]bool),
		lastIO:    make(map[int]struct{ read, write uint64 }),
		lastNet:   make(map[int]struct{ sent, recv uint64 }),
	}
}

func (pm *ProcessMonitor) SetCallbacks(onNew func(*models.ProcessInfo), onExit func(int)) {
	pm.onNewProcess = onNew
	pm.onProcessExit = onExit
}

func (pm *ProcessMonitor) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	pm.scanProcesses()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.scanProcesses()
		}
	}
}

func (pm *ProcessMonitor) scanProcesses() {
	procs, err := psproc.Processes()
	if err != nil {
		return
	}

	currentPIDs := make(map[int]bool)

	for _, p := range procs {
		pid := int(p.Pid)
		currentPIDs[pid] = true

		info := pm.collectProcessInfo(p)
		if info == nil {
			continue
		}

		pm.mu.RLock()
		_, exists := pm.monitored[pid]
		pm.mu.RUnlock()

		if !exists && pm.onNewProcess != nil {
			pm.onNewProcess(info)
		}

		pm.mu.Lock()
		pm.monitored[pid] = true
		pm.mu.Unlock()

		go pm.db.SaveProcess(info)
	}

	pm.mu.Lock()
	for pid := range pm.monitored {
		if !currentPIDs[pid] {
			delete(pm.monitored, pid)
			delete(pm.lastIO, pid)
			delete(pm.lastNet, pid)
			if pm.onProcessExit != nil {
				go pm.onProcessExit(pid)
			}
			go pm.db.SaveProcessEvent(&models.ProcessEvent{
				PID:       pid,
				EventType: "exit",
				Timestamp: time.Now(),
			})
		}
	}
	pm.mu.Unlock()
}

func (pm *ProcessMonitor) collectProcessInfo(p *psproc.Process) *models.ProcessInfo {
	pid := int(p.Pid)
	info := &models.ProcessInfo{
		PID:       pid,
		Timestamp: time.Now(),
	}

	if name, err := p.Name(); err == nil {
		info.Name = name
	}

	if cmdline, err := p.Cmdline(); err == nil {
		info.CmdLine = cmdline
	}

	if ppid, err := p.Ppid(); err == nil {
		info.PPID = int(ppid)
	}

	if exe, err := p.Exe(); err == nil {
		info.ExePath = exe
	}

	if cwd, err := p.Cwd(); err == nil {
		info.CWD = cwd
	}

	if username, err := p.Username(); err == nil {
		info.User = username
	}

	if createTime, err := p.CreateTime(); err == nil {
		info.CreateTime = createTime
	}

	if status, err := p.Status(); err == nil && len(status) > 0 {
		info.Status = status[0]
	}

	if numThreads, err := p.NumThreads(); err == nil {
		info.NumThreads = numThreads
	}

	if numFDs, err := p.NumFDs(); err == nil {
		info.NumFDs = numFDs
	}

	if cpu, err := p.CPUPercent(); err == nil {
		info.CPU = cpu
	}

	if memInfo, err := p.MemoryInfo(); err == nil {
		info.MemoryRSS = memInfo.RSS
		info.MemoryVMS = memInfo.VMS
	}

	if memPercent, err := p.MemoryPercent(); err == nil {
		info.Memory = float64(memPercent)
	}

	ioRead, ioWrite := pm.getProcessIO(pid)
	info.IOReadBytes = ioRead
	info.IOWriteBytes = ioWrite

	pm.mu.Lock()
	if last, ok := pm.lastIO[pid]; ok {
		info.IOReadRate = ioRead - last.read
		info.IOWriteRate = ioWrite - last.write
	}
	pm.lastIO[pid] = struct{ read, write uint64 }{ioRead, ioWrite}
	pm.mu.Unlock()

	conns := pm.getProcessConnections(pid)
	info.NumConns = len(conns)

	for _, conn := range conns {
		go pm.db.SaveNetworkConnection(conn)
	}

	pm.mu.RLock()
	info.IsMonitored = pm.monitored[pid]
	pm.mu.RUnlock()

	return info
}

func (pm *ProcessMonitor) getProcessIO(pid int) (readBytes, writeBytes uint64) {
	path := fmt.Sprintf("/proc/%d/io", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "read_bytes:") {
			val := strings.TrimSpace(line[len("read_bytes:"):])
			readBytes, _ = strconv.ParseUint(val, 10, 64)
		} else if strings.HasPrefix(line, "write_bytes:") {
			val := strings.TrimSpace(line[len("write_bytes:"):])
			writeBytes, _ = strconv.ParseUint(val, 10, 64)
		}
	}
	return
}

func (pm *ProcessMonitor) getProcessConnections(pid int) []*models.NetworkConnection {
	var connections []*models.NetworkConnection

	inodeMap := pm.parseProcNet("tcp")
	for k, v := range pm.parseProcNet("tcp6") {
		inodeMap[k] = v
	}
	for k, v := range pm.parseProcNet("udp") {
		inodeMap[k] = v
	}
	for k, v := range pm.parseProcNet("udp6") {
		inodeMap[k] = v
	}

	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return connections
	}

	seenInodes := make(map[string]bool)
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}

		if strings.HasPrefix(link, "socket:[") {
			inode := strings.Trim(link[len("socket:["):len(link)-1], "[]")
			if seenInodes[inode] {
				continue
			}
			seenInodes[inode] = true

			if conn, ok := inodeMap[inode]; ok {
				conn.PID = pid
				conn.Timestamp = time.Now()
				connections = append(connections, conn)
			}
		}
	}

	return connections
}

func (pm *ProcessMonitor) parseProcNet(proto string) map[string]*models.NetworkConnection {
	result := make(map[string]*models.NetworkConnection)

	path := fmt.Sprintf("/proc/net/%s", proto)
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || len(line) == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		local := fields[1]
		remote := fields[2]
		state := fields[3]
		inode := fields[9]

		localParts := strings.Split(local, ":")
		remoteParts := strings.Split(remote, ":")
		if len(localParts) != 2 || len(remoteParts) != 2 {
			continue
		}

		conn := &models.NetworkConnection{
			Proto:      proto,
			LocalIP:    utils.ParseHexIP(localParts[0]),
			LocalPort:  utils.ParseHexPort(localParts[1]),
			RemoteIP:   utils.ParseHexIP(remoteParts[0]),
			RemotePort: utils.ParseHexPort(remoteParts[1]),
			State:      utils.ParseProcNetState(state),
			Inode:      inode,
		}

		result[inode] = conn
	}

	return result
}

func (pm *ProcessMonitor) GetProcessTree() *models.ProcessTreeNode {
	procs, err := psproc.Processes()
	if err != nil {
		return nil
	}

	procMap := make(map[int]*psproc.Process)
	pidToPPID := make(map[int]int)

	for _, p := range procs {
		pid := int(p.Pid)
		procMap[pid] = p
		if ppid, err := p.Ppid(); err == nil {
			pidToPPID[pid] = int(ppid)
		}
	}

	root := &models.ProcessTreeNode{PID: 0, Name: "init"}
	children := make(map[int][]*models.ProcessTreeNode)

	for pid, p := range procMap {
		name, _ := p.Name()
		cpu, _ := p.CPUPercent()
		mem, _ := p.MemoryPercent()

		node := &models.ProcessTreeNode{
			PID:    pid,
			Name:   name,
			CPU:    cpu,
			Memory: float64(mem),
		}

		ppid := pidToPPID[pid]
		children[ppid] = append(children[ppid], node)
	}

	pm.attachChildren(root, children)

	return root
}

func (pm *ProcessMonitor) attachChildren(parent *models.ProcessTreeNode, children map[int][]*models.ProcessTreeNode) {
	parent.Children = children[parent.PID]
	for _, child := range parent.Children {
		pm.attachChildren(child, children)
	}
}

func (pm *ProcessMonitor) GetOpenFiles(pid int) ([]*models.OpenFile, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	var files []*models.OpenFile
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}

		fileType := utils.GetFileType(link)
		files = append(files, &models.OpenFile{
			PID:       pid,
			FD:        fd,
			Path:      link,
			Type:      fileType,
			Timestamp: time.Now(),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].FD < files[j].FD
	})

	return files, nil
}

func (pm *ProcessMonitor) GetModules(pid int) ([]*models.Module, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var modules []*models.Module

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		path := fields[len(fields)-1]
		if strings.HasPrefix(path, "[") || path == "" {
			continue
		}

		if seen[path] {
			continue
		}
		seen[path] = true

		info, err := os.Stat(path)
		var size int64
		if err == nil {
			size = info.Size()
		}

		modules = append(modules, &models.Module{
			PID:       pid,
			Name:      filepath.Base(path),
			Path:      path,
			Size:      uint64(size),
			Timestamp: time.Now(),
		})
	}

	return modules, nil
}

type SystemMonitor struct {
	db      *database.DB
	lastNet psnet.IOCountersStat
	mu      sync.Mutex
}

func NewSystemMonitor(db *database.DB) *SystemMonitor {
	return &SystemMonitor{db: db}
}

func (sm *SystemMonitor) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.collectStats()
		}
	}
}

func (sm *SystemMonitor) collectStats() {
	stats := &models.SystemStats{
		Timestamp: time.Now(),
	}

	if cpuPercents, err := pscpu.PercentWithContext(context.Background(), 0, false); err == nil && len(cpuPercents) > 0 {
		stats.CPU = cpuPercents[0]
	}

	if mem, err := psmem.VirtualMemory(); err == nil {
		stats.Memory = mem.UsedPercent
		stats.MemoryUsed = mem.Used
		stats.MemoryTotal = mem.Total
	}

	if disk, err := psdisk.Usage("/"); err == nil {
		stats.DiskUsed = disk.Used
		stats.DiskTotal = disk.Total
		stats.DiskPercent = disk.UsedPercent
	}

	if netIOs, err := psnet.IOCounters(false); err == nil && len(netIOs) > 0 {
		netIO := netIOs[0]
		stats.NetSent = netIO.BytesSent
		stats.NetRecv = netIO.BytesRecv

		sm.mu.Lock()
		stats.NetSentRate = netIO.BytesSent - sm.lastNet.BytesSent
		stats.NetRecvRate = netIO.BytesRecv - sm.lastNet.BytesRecv
		sm.lastNet = netIO
		sm.mu.Unlock()
	}

	loadAvg, err := psload.Avg()
	if err == nil {
		stats.LoadAvg1 = loadAvg.Load1
		stats.LoadAvg5 = loadAvg.Load5
		stats.LoadAvg15 = loadAvg.Load15
	}

	go sm.db.SaveSystemStats(stats)
}

func GetTopProcesses(byCPU bool, limit int) ([]*models.ProcessInfo, error) {
	procs, err := psproc.Processes()
	if err != nil {
		return nil, err
	}

	var infos []*models.ProcessInfo
	for _, p := range procs {
		info := &models.ProcessInfo{PID: int(p.Pid)}
		if name, err := p.Name(); err == nil {
			info.Name = name
		}
		if cpu, err := p.CPUPercent(); err == nil {
			info.CPU = cpu
		}
		if mem, err := p.MemoryPercent(); err == nil {
			info.Memory = float64(mem)
		}
		infos = append(infos, info)
	}

	if byCPU {
		sort.Slice(infos, func(i, j int) bool {
			return infos[i].CPU > infos[j].CPU
		})
	} else {
		sort.Slice(infos, func(i, j int) bool {
			return infos[i].Memory > infos[j].Memory
		})
	}

	if len(infos) > limit {
		infos = infos[:limit]
	}
	return infos, nil
}

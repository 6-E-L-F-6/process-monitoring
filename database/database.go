package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/models"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	conn *sql.DB
	mu   sync.RWMutex
	path string
}

func New(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	conn, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_temp_store=memory")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(time.Hour)

	db := &DB{
		conn: conn,
		path: dbPath,
	}

	if err := db.createTables(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.conn.Close()
}

func (db *DB) createTables() error {
	schema := `
-- Processes table
CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    ppid INTEGER DEFAULT 0,
    name TEXT,
    cmdline TEXT,
    exe_path TEXT,
    cwd TEXT,
    user TEXT,
    cpu_percent REAL DEFAULT 0,
    memory_percent REAL DEFAULT 0,
    memory_rss INTEGER DEFAULT 0,
    memory_vms INTEGER DEFAULT 0,
    io_read_bytes INTEGER DEFAULT 0,
    io_write_bytes INTEGER DEFAULT 0,
    io_read_rate INTEGER DEFAULT 0,
    io_write_rate INTEGER DEFAULT 0,
    num_threads INTEGER DEFAULT 0,
    num_fds INTEGER DEFAULT 0,
    num_connections INTEGER DEFAULT 0,
    status TEXT,
    create_time INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_monitored INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_timestamp ON processes(timestamp);
CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);

-- Network connections table
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    protocol TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    state TEXT,
    inode TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_net_pid ON network_connections(pid);
CREATE INDEX IF NOT EXISTS idx_net_timestamp ON network_connections(timestamp);

-- File events table
CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    process_name TEXT,
    operation TEXT,
    path TEXT,
    size INTEGER DEFAULT 0,
    hash TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_files_pid ON file_events(pid);
CREATE INDEX IF NOT EXISTS idx_files_timestamp ON file_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_files_path ON file_events(path);

-- Memory dumps table
CREATE TABLE IF NOT EXISTS memory_dumps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    process_name TEXT,
    start_addr INTEGER,
    end_addr INTEGER,
    size INTEGER,
    file_path TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_memory_pid ON memory_dumps(pid);

-- Process events table
CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    name TEXT,
    cmdline TEXT,
    event_type TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_pid ON process_events(pid);
CREATE INDEX IF NOT EXISTS idx_events_type ON process_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON process_events(timestamp);

-- System stats table
CREATE TABLE IF NOT EXISTS system_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cpu_percent REAL,
    memory_percent REAL,
    memory_used INTEGER,
    memory_total INTEGER,
    disk_used INTEGER,
    disk_total INTEGER,
    disk_percent REAL,
    net_sent INTEGER,
    net_recv INTEGER,
    net_sent_rate INTEGER,
    net_recv_rate INTEGER,
    load_avg_1 REAL,
    load_avg_5 REAL,
    load_avg_15 REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON system_stats(timestamp);

-- Open files table
CREATE TABLE IF NOT EXISTS open_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    fd INTEGER,
    path TEXT,
    type TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_open_files_pid ON open_files(pid);

-- Modules table
CREATE TABLE IF NOT EXISTS modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    name TEXT,
    path TEXT,
    size INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_modules_pid ON modules(pid);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    process_name TEXT,
    alert_type TEXT,
    severity TEXT,
    message TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    acknowledged INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_pid ON alerts(pid);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);

-- Maintenance: keep only last 7 days of data
CREATE TRIGGER IF NOT EXISTS cleanup_old_processes 
AFTER INSERT ON processes
BEGIN
    DELETE FROM processes WHERE timestamp < datetime('now', '-7 days');
END;

CREATE TRIGGER IF NOT EXISTS cleanup_old_connections 
AFTER INSERT ON network_connections
BEGIN
    DELETE FROM network_connections WHERE timestamp < datetime('now', '-7 days');
END;

CREATE TRIGGER IF NOT EXISTS cleanup_old_file_events 
AFTER INSERT ON file_events
BEGIN
    DELETE FROM file_events WHERE timestamp < datetime('now', '-7 days');
END;

CREATE TRIGGER IF NOT EXISTS cleanup_old_stats 
AFTER INSERT ON system_stats
BEGIN
    DELETE FROM system_stats WHERE timestamp < datetime('now', '-3 days');
END;
`
	_, err := db.conn.Exec(schema)
	return err
}

func (db *DB) SaveProcess(p *models.ProcessInfo) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO processes (
			pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		p.PID, p.PPID, p.Name, p.CmdLine, p.ExePath, p.CWD, p.User,
		p.CPU, p.Memory, p.MemoryRSS, p.MemoryVMS,
		p.IOReadBytes, p.IOWriteBytes, p.IOReadRate, p.IOWriteRate,
		p.NumThreads, p.NumFDs, p.NumConns, p.Status, p.CreateTime,
		p.Timestamp, boolToInt(p.IsMonitored),
	)
	return err
}

func (db *DB) SaveNetworkConnection(nc *models.NetworkConnection) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO network_connections (pid, protocol, local_ip, local_port, remote_ip, remote_port, state, inode, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		nc.PID, nc.Proto, nc.LocalIP, nc.LocalPort, nc.RemoteIP, nc.RemotePort, nc.State, nc.Inode, nc.Timestamp,
	)
	return err
}

func (db *DB) SaveFileEvent(fe *models.FileEvent) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO file_events (pid, process_name, operation, path, size, hash, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		fe.PID, fe.ProcessName, fe.Operation, fe.Path, fe.Size, fe.Hash, fe.Timestamp,
	)
	return err
}

func (db *DB) SaveMemoryDump(md *models.MemoryDump) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO memory_dumps (pid, process_name, start_addr, end_addr, size, file_path, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		md.PID, md.ProcessName, md.StartAddr, md.EndAddr, md.Size, md.FilePath, md.Timestamp,
	)
	return err
}

func (db *DB) SaveProcessEvent(pe *models.ProcessEvent) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO process_events (pid, ppid, name, cmdline, event_type, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		pe.PID, pe.PPID, pe.Name, pe.CmdLine, pe.EventType, pe.Timestamp,
	)
	return err
}

func (db *DB) SaveSystemStats(ss *models.SystemStats) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO system_stats (
			cpu_percent, memory_percent, memory_used, memory_total,
			disk_used, disk_total, disk_percent,
			net_sent, net_recv, net_sent_rate, net_recv_rate,
			load_avg_1, load_avg_5, load_avg_15, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		ss.CPU, ss.Memory, ss.MemoryUsed, ss.MemoryTotal,
		ss.DiskUsed, ss.DiskTotal, ss.DiskPercent,
		ss.NetSent, ss.NetRecv, ss.NetSentRate, ss.NetRecvRate,
		ss.LoadAvg1, ss.LoadAvg5, ss.LoadAvg15, ss.Timestamp,
	)
	return err
}

func (db *DB) SaveOpenFile(of *models.OpenFile) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO open_files (pid, fd, path, type, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query, of.PID, of.FD, of.Path, of.Type, of.Timestamp)
	return err
}

func (db *DB) SaveModule(m *models.Module) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO modules (pid, name, path, size, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query, m.PID, m.Name, m.Path, m.Size, m.Timestamp)
	return err
}

func (db *DB) SaveAlert(a *models.Alert) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `
		INSERT INTO alerts (pid, process_name, alert_type, severity, message, details, timestamp, acknowledged)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query,
		a.PID, a.ProcessName, a.AlertType, a.Severity, a.Message, a.Details, a.Timestamp, boolToInt(a.Acknowledged),
	)
	return err
}

func (db *DB) GetProcesses(limit int, offset int) ([]*models.ProcessInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		FROM processes
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`
	rows, err := db.conn.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var processes []*models.ProcessInfo
	for rows.Next() {
		p := &models.ProcessInfo{}
		var isMonitored int
		err := rows.Scan(
			&p.PID, &p.PPID, &p.Name, &p.CmdLine, &p.ExePath, &p.CWD, &p.User,
			&p.CPU, &p.Memory, &p.MemoryRSS, &p.MemoryVMS,
			&p.IOReadBytes, &p.IOWriteBytes, &p.IOReadRate, &p.IOWriteRate,
			&p.NumThreads, &p.NumFDs, &p.NumConns, &p.Status, &p.CreateTime, &p.Timestamp, &isMonitored,
		)
		if err != nil {
			continue
		}
		p.IsMonitored = isMonitored == 1
		processes = append(processes, p)
	}
	return processes, nil
}

func (db *DB) GetProcessByPID(pid int) (*models.ProcessInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		FROM processes
		WHERE pid = ?
		ORDER BY timestamp DESC
		LIMIT 1
	`
	p := &models.ProcessInfo{}
	var isMonitored int
	err := db.conn.QueryRow(query, pid).Scan(
		&p.PID, &p.PPID, &p.Name, &p.CmdLine, &p.ExePath, &p.CWD, &p.User,
		&p.CPU, &p.Memory, &p.MemoryRSS, &p.MemoryVMS,
		&p.IOReadBytes, &p.IOWriteBytes, &p.IOReadRate, &p.IOWriteRate,
		&p.NumThreads, &p.NumFDs, &p.NumConns, &p.Status, &p.CreateTime, &p.Timestamp, &isMonitored,
	)
	if err != nil {
		return nil, err
	}
	p.IsMonitored = isMonitored == 1
	return p, nil
}

func (db *DB) GetNetworkConnectionsByPID(pid int) ([]*models.NetworkConnection, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT id, pid, protocol, local_ip, local_port, remote_ip, remote_port, state, inode, timestamp
		FROM network_connections
		WHERE pid = ?
		ORDER BY timestamp DESC
	`
	rows, err := db.conn.Query(query, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []*models.NetworkConnection
	for rows.Next() {
		nc := &models.NetworkConnection{}
		err := rows.Scan(&nc.ID, &nc.PID, &nc.Proto, &nc.LocalIP, &nc.LocalPort, &nc.RemoteIP, &nc.RemotePort, &nc.State, &nc.Inode, &nc.Timestamp)
		if err != nil {
			continue
		}
		conns = append(conns, nc)
	}
	return conns, nil
}

func (db *DB) GetFileEventsByPID(pid int, limit int) ([]*models.FileEvent, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT id, pid, process_name, operation, path, size, hash, timestamp
		FROM file_events
		WHERE pid = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := db.conn.Query(query, pid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.FileEvent
	for rows.Next() {
		fe := &models.FileEvent{}
		err := rows.Scan(&fe.ID, &fe.PID, &fe.ProcessName, &fe.Operation, &fe.Path, &fe.Size, &fe.Hash, &fe.Timestamp)
		if err != nil {
			continue
		}
		events = append(events, fe)
	}
	return events, nil
}

func (db *DB) GetAlerts(acknowledged bool, severity string, limit int) ([]*models.Alert, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT id, pid, process_name, alert_type, severity, message, details, timestamp, acknowledged
		FROM alerts
		WHERE acknowledged = ? AND (? = '' OR severity = ?)
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := db.conn.Query(query, boolToInt(acknowledged), severity, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var ack int
		err := rows.Scan(&a.ID, &a.PID, &a.ProcessName, &a.AlertType, &a.Severity, &a.Message, &a.Details, &a.Timestamp, &ack)
		if err != nil {
			continue
		}
		a.Acknowledged = ack == 1
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func (db *DB) AcknowledgeAlert(id int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec("UPDATE alerts SET acknowledged = 1 WHERE id = ?", id)
	return err
}

func (db *DB) GetProcessHistory(pid int, startTime, endTime time.Time) ([]*models.ProcessInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		FROM processes
		WHERE pid = ? AND timestamp BETWEEN ? AND ?
		ORDER BY timestamp ASC
	`
	rows, err := db.conn.Query(query, pid, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var processes []*models.ProcessInfo
	for rows.Next() {
		p := &models.ProcessInfo{}
		var isMonitored int
		err := rows.Scan(
			&p.PID, &p.PPID, &p.Name, &p.CmdLine, &p.ExePath, &p.CWD, &p.User,
			&p.CPU, &p.Memory, &p.MemoryRSS, &p.MemoryVMS,
			&p.IOReadBytes, &p.IOWriteBytes, &p.IOReadRate, &p.IOWriteRate,
			&p.NumThreads, &p.NumFDs, &p.NumConns, &p.Status, &p.CreateTime, &p.Timestamp, &isMonitored,
		)
		if err != nil {
			continue
		}
		p.IsMonitored = isMonitored == 1
		processes = append(processes, p)
	}
	return processes, nil
}

func (db *DB) GetLatestSystemStats() (*models.SystemStats, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT id, cpu_percent, memory_percent, memory_used, memory_total,
			disk_used, disk_total, disk_percent,
			net_sent, net_recv, net_sent_rate, net_recv_rate,
			load_avg_1, load_avg_5, load_avg_15, timestamp
		FROM system_stats
		ORDER BY timestamp DESC
		LIMIT 1
	`
	ss := &models.SystemStats{}
	err := db.conn.QueryRow(query).Scan(
		&ss.ID, &ss.CPU, &ss.Memory, &ss.MemoryUsed, &ss.MemoryTotal,
		&ss.DiskUsed, &ss.DiskTotal, &ss.DiskPercent,
		&ss.NetSent, &ss.NetRecv, &ss.NetSentRate, &ss.NetRecvRate,
		&ss.LoadAvg1, &ss.LoadAvg5, &ss.LoadAvg15, &ss.Timestamp,
	)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (db *DB) GetTopProcessesByCPU(limit int) ([]*models.ProcessInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		FROM processes
		WHERE timestamp > datetime('now', '-1 minute')
		GROUP BY pid
		ORDER BY cpu_percent DESC
		LIMIT ?
	`
	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var processes []*models.ProcessInfo
	for rows.Next() {
		p := &models.ProcessInfo{}
		var isMonitored int
		err := rows.Scan(
			&p.PID, &p.PPID, &p.Name, &p.CmdLine, &p.ExePath, &p.CWD, &p.User,
			&p.CPU, &p.Memory, &p.MemoryRSS, &p.MemoryVMS,
			&p.IOReadBytes, &p.IOWriteBytes, &p.IOReadRate, &p.IOWriteRate,
			&p.NumThreads, &p.NumFDs, &p.NumConns, &p.Status, &p.CreateTime, &p.Timestamp, &isMonitored,
		)
		if err != nil {
			continue
		}
		p.IsMonitored = isMonitored == 1
		processes = append(processes, p)
	}
	return processes, nil
}

func (db *DB) GetTopProcessesByMemory(limit int) ([]*models.ProcessInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		FROM processes
		WHERE timestamp > datetime('now', '-1 minute')
		GROUP BY pid
		ORDER BY memory_percent DESC
		LIMIT ?
	`
	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var processes []*models.ProcessInfo
	for rows.Next() {
		p := &models.ProcessInfo{}
		var isMonitored int
		err := rows.Scan(
			&p.PID, &p.PPID, &p.Name, &p.CmdLine, &p.ExePath, &p.CWD, &p.User,
			&p.CPU, &p.Memory, &p.MemoryRSS, &p.MemoryVMS,
			&p.IOReadBytes, &p.IOWriteBytes, &p.IOReadRate, &p.IOWriteRate,
			&p.NumThreads, &p.NumFDs, &p.NumConns, &p.Status, &p.CreateTime, &p.Timestamp, &isMonitored,
		)
		if err != nil {
			continue
		}
		p.IsMonitored = isMonitored == 1
		processes = append(processes, p)
	}
	return processes, nil
}

func (db *DB) SearchProcesses(name string, pid int, minCPU, minMemory float64) ([]*models.ProcessInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `
		SELECT pid, ppid, name, cmdline, exe_path, cwd, user,
			cpu_percent, memory_percent, memory_rss, memory_vms,
			io_read_bytes, io_write_bytes, io_read_rate, io_write_rate,
			num_threads, num_fds, num_connections, status, create_time, timestamp, is_monitored
		FROM processes
		WHERE timestamp > datetime('now', '-1 minute')
		AND (? = '' OR name LIKE ?)
		AND (? = 0 OR pid = ?)
		AND cpu_percent >= ?
		AND memory_percent >= ?
		GROUP BY pid
		ORDER BY timestamp DESC
		LIMIT 100
	`
	namePattern := "%" + name + "%"
	rows, err := db.conn.Query(query, name, namePattern, pid, pid, minCPU, minMemory)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var processes []*models.ProcessInfo
	for rows.Next() {
		p := &models.ProcessInfo{}
		var isMonitored int
		err := rows.Scan(
			&p.PID, &p.PPID, &p.Name, &p.CmdLine, &p.ExePath, &p.CWD, &p.User,
			&p.CPU, &p.Memory, &p.MemoryRSS, &p.MemoryVMS,
			&p.IOReadBytes, &p.IOWriteBytes, &p.IOReadRate, &p.IOWriteRate,
			&p.NumThreads, &p.NumFDs, &p.NumConns, &p.Status, &p.CreateTime, &p.Timestamp, &isMonitored,
		)
		if err != nil {
			continue
		}
		p.IsMonitored = isMonitored == 1
		processes = append(processes, p)
	}
	return processes, nil
}

func (db *DB) DeleteOldData() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	tables := []string{
		"processes",
		"network_connections",
		"file_events",
		"process_events",
		"system_stats",
	}

	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE timestamp < datetime('now', '-7 days')", table)
		if _, err := db.conn.Exec(query); err != nil {
			return err
		}
	}

	_, err := db.conn.Exec("VACUUM")
	return err
}

func (db *DB) GetDBSize() (int64, error) {
	info, err := os.Stat(db.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

# Process Monitor - Professional Malware Analysis Tool

**Created By E | L F**

A comprehensive, professional-grade process monitoring and malware analysis tool for Linux systems.

## Features

### Core Monitoring
- **Real-time Process Monitoring**: Track all running processes with CPU, memory, I/O, and network usage
- **System Statistics**: Monitor overall system health including CPU, memory, disk, and network
- **Process Tree**: Visualize process hierarchy and relationships
- **Network Connections**: Track all network connections per process with protocol details
- **File System Activity**: Monitor file operations performed by processes
- **Memory Analysis**: Dump and analyze process memory

### Malware Analysis Features
- **Memory Dumping**: Full or selective memory dumps of suspicious processes
- **Network Traffic Analysis**: Track all inbound/outbound connections
- **File Activity Tracking**: Monitor file creation, modification, and deletion
- **Behavioral Analysis**: Detect suspicious patterns and anomalies
- **Alert System**: Automatic alerts for suspicious activities

### Data Management
- **SQLite3 Database**: All data stored in a structured SQLite database
- **JSON Export**: Export process data, history, and analysis results to JSON
- **Log Files**: Text-based logs for easy parsing
- **Data Retention**: Automatic cleanup of old data (7-day retention)

### User Interface
- **Professional TUI**: Terminal-based user interface with real-time updates
- **Interactive Controls**: Keyboard shortcuts for all operations
- **Color Coding**: Visual indicators for resource usage and alerts
- **Search & Filter**: Find processes by name, PID, or resource usage

## Installation

### Prerequisites
- Go 1.21 or higher
- Linux operating system
- SQLite3 development libraries

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libsqlite3-dev

# Clone and build
cd procmon
go mod download
go build -o procmon
```

## Usage

### Basic Usage
```bash
# Run in monitoring mode (default)
sudo ./procmon

# Specify custom database location
sudo ./procmon -db /var/lib/procmon/data.db

# Adjust monitoring interval
sudo ./procmon -interval 2s
```

### Export Mode
```bash
# Export specific process to JSON
./procmon -mode export -pid 1234 -output process_1234.json

# Export all processes
./procmon -mode export -output all_processes.json
```

### Command Line Options
```
-db string
    Database file path (default "./data/procmon.db")
-dump string
    Memory dump directory (default "./dumps")
-interval duration
    Monitoring interval (default 1s)
-log string
    Log directory (default "./logs")
-mode string
    Mode: monitor, export, or viewer (default "monitor")
-output string
    Export output path
-pid int
    PID to export (for export mode)
-version
    Show version
```

## Keyboard Shortcuts

### Navigation
- `↑/↓` - Navigate process list
- `Enter` - Lock detail view to selected process
- `Esc` - Unlock detail view
- `Tab` - Switch focus

### Actions
- `r` or `Ctrl+R` - Refresh process list
- `d` or `Ctrl+D` - Dump process memory
- `e` or `Ctrl+E` - Export process data to JSON
- `l` or `Ctrl+L` - Toggle process logging
- `a` or `Ctrl+A` - Show alerts
- `k` - Kill selected process

### System
- `h` or `?` or `Ctrl+H` - Show help
- `q` or `Ctrl+C` or `Ctrl+Q` - Quit

## Database Schema

### Tables
- **processes** - Process information snapshots
- **network_connections** - Network connection tracking
- **file_events** - File system operations
- **memory_dumps** - Memory dump metadata
- **process_events** - Process lifecycle events
- **system_stats** - System-wide statistics
- **open_files** - Open file descriptors
- **modules** - Loaded libraries/modules
- **alerts** - Security alerts


## Project Structure
```
procmon/
├── database/       # Database layer
│   └── database.go
├── exporter/       # JSON export functionality
│   └── exporter.go
├── logger/         # Logging system
│   └── logger.go
├── models/         # Data models
│   └── models.go
├── monitor/        # Monitoring components
│   ├── process.go  # Process monitoring
│   ├── file.go     # File system monitoring
│   └── memory.go   # Memory operations
├── ui/             # User interface
│   └── ui.go
├── utils/          # Utility functions
│   └── helpers.go
├── main.go         # Entry point
├── go.mod          # Go module
└── README.md       # This file
```

## Security Considerations

- **Root Privileges**: Some features require root access (memory dumps, all processes)
- **Memory Dumps**: Can contain sensitive data - store securely
- **Database**: Contains system information - protect appropriately
- **Alerts**: Configure thresholds to avoid alert fatigue

## Troubleshooting

### Permission Denied
Run with sudo for full functionality:
```bash
sudo ./procmon
```

### Database Locked
If the database is locked, check for other instances:
```bash
lsof data/procmon.db
```

### High CPU Usage
Increase the monitoring interval:
```bash
sudo ./procmon -interval 5s
```

## License

Created By E | L F

## Version History

- v2.0.0 - Complete rewrite with SQLite3, modular architecture, professional UI
- v1.0.0 - Initial version

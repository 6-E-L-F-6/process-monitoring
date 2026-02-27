package monitor

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/6-E-L-F-6/process-monitoring/database"
	"github.com/6-E-L-F-6/process-monitoring/models"
	"github.com/6-E-L-F-6/process-monitoring/utils"
)

type MemoryDumper struct {
	db      *database.DB
	dumpDir string
}

func NewMemoryDumper(db *database.DB, dumpDir string) (*MemoryDumper, error) {
	if err := os.MkdirAll(dumpDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create dump directory: %w", err)
	}

	return &MemoryDumper{
		db:      db,
		dumpDir: dumpDir,
	}, nil
}

func (md *MemoryDumper) DumpProcessMemory(pid int) (string, error) {
	procName := utils.GetProcessName(pid)
	timestamp := time.Now().Format("20060102_150405")
	dumpFile := filepath.Join(md.dumpDir, fmt.Sprintf("dump_%d_%s_%s.bin", pid, procName, timestamp))

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return "", fmt.Errorf("failed to open process memory: %w", err)
	}
	defer memFile.Close()

	outFile, err := os.Create(dumpFile)
	if err != nil {
		return "", fmt.Errorf("failed to create dump file: %w", err)
	}
	defer outFile.Close()

	maps, err := md.parseMemoryMaps(pid)
	if err != nil {
		return "", fmt.Errorf("failed to parse memory maps: %w", err)
	}

	var totalDumped uint64
	writer := bufio.NewWriter(outFile)

	for _, region := range maps {
		if !region.Readable || region.Size == 0 {
			continue
		}

		size, err := md.dumpMemoryRegion(memFile, writer, region)
		if err != nil {
			continue
		}
		totalDumped += size
	}

	writer.Flush()

	md.db.SaveMemoryDump(&models.MemoryDump{
		PID:         pid,
		ProcessName: procName,
		StartAddr:   0,
		EndAddr:     0,
		Size:        totalDumped,
		FilePath:    dumpFile,
		Timestamp:   time.Now(),
	})

	return dumpFile, nil
}

func (md *MemoryDumper) DumpMemoryRegion(pid int, startAddr, endAddr uint64) (string, error) {
	procName := utils.GetProcessName(pid)
	timestamp := time.Now().Format("20060102_150405")
	dumpFile := filepath.Join(md.dumpDir, fmt.Sprintf("dump_%d_%s_%s_%x-%x.bin", pid, procName, timestamp, startAddr, endAddr))

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return "", fmt.Errorf("failed to open process memory: %w", err)
	}
	defer memFile.Close()

	outFile, err := os.Create(dumpFile)
	if err != nil {
		return "", fmt.Errorf("failed to create dump file: %w", err)
	}
	defer outFile.Close()

	_, err = memFile.Seek(int64(startAddr), 0)
	if err != nil {
		return "", fmt.Errorf("failed to seek to address: %w", err)
	}

	size := endAddr - startAddr
	buffer := make([]byte, 4096)
	var written uint64

	for written < size {
		toRead := uint64(len(buffer))
		if remaining := size - written; remaining < toRead {
			toRead = remaining
		}

		n, err := memFile.Read(buffer[:toRead])
		if err != nil {
			break
		}

		outFile.Write(buffer[:n])
		written += uint64(n)
	}

	md.db.SaveMemoryDump(&models.MemoryDump{
		PID:         pid,
		ProcessName: procName,
		StartAddr:   startAddr,
		EndAddr:     endAddr,
		Size:        written,
		FilePath:    dumpFile,
		Timestamp:   time.Now(),
	})

	return dumpFile, nil
}

type memoryRegion struct {
	Start      uint64
	End        uint64
	Size       uint64
	Readable   bool
	Writable   bool
	Executable bool
	Private    bool
	Path       string
}

func (md *MemoryDumper) parseMemoryMaps(pid int) ([]*memoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, err
	}

	var regions []*memoryRegion
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		region := md.parseMapLine(line)
		if region != nil {
			regions = append(regions, region)
		}
	}

	return regions, nil
}

func (md *MemoryDumper) parseMapLine(line string) *memoryRegion {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	addrRange := strings.Split(parts[0], "-")
	if len(addrRange) != 2 {
		return nil
	}

	start, err1 := strconv.ParseUint(addrRange[0], 16, 64)
	end, err2 := strconv.ParseUint(addrRange[1], 16, 64)
	if err1 != nil || err2 != nil {
		return nil
	}

	perms := parts[1]
	if len(perms) < 4 {
		return nil
	}

	region := &memoryRegion{
		Start:      start,
		End:        end,
		Size:       end - start,
		Readable:   perms[0] == 'r',
		Writable:   perms[1] == 'w',
		Executable: perms[2] == 'x',
		Private:    perms[3] == 'p',
	}

	if len(parts) >= 6 {
		region.Path = strings.Join(parts[5:], " ")
	}

	return region
}

func (md *MemoryDumper) dumpMemoryRegion(memFile *os.File, writer *bufio.Writer, region *memoryRegion) (uint64, error) {
	_, err := memFile.Seek(int64(region.Start), 0)
	if err != nil {
		return 0, err
	}

	buffer := make([]byte, 4096)
	var totalRead uint64
	regionSize := region.Size

	for totalRead < regionSize {
		toRead := uint64(len(buffer))
		if remaining := regionSize - totalRead; remaining < toRead {
			toRead = remaining
		}

		n, err := memFile.Read(buffer[:toRead])
		if err != nil {
			break
		}

		writer.Write(buffer[:n])
		totalRead += uint64(n)
	}

	return totalRead, nil
}

func (md *MemoryDumper) GetMemoryMaps(pid int) ([]map[string]interface{}, error) {
	regions, err := md.parseMemoryMaps(pid)
	if err != nil {
		return nil, err
	}

	var maps []map[string]interface{}
	for _, r := range regions {
		maps = append(maps, map[string]interface{}{
			"start":      fmt.Sprintf("0x%016x", r.Start),
			"end":        fmt.Sprintf("0x%016x", r.End),
			"size":       utils.HumanBytes(r.Size),
			"readable":   r.Readable,
			"writable":   r.Writable,
			"executable": r.Executable,
			"private":    r.Private,
			"path":       r.Path,
		})
	}

	return maps, nil
}

func (md *MemoryDumper) SearchMemory(pid int, pattern []byte) ([]uint64, error) {
	var addresses []uint64

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, err
	}
	defer memFile.Close()

	regions, err := md.parseMemoryMaps(pid)
	if err != nil {
		return nil, err
	}

	for _, region := range regions {
		if !region.Readable {
			continue
		}

		addrs := md.searchRegion(memFile, region, pattern)
		addresses = append(addresses, addrs...)
	}

	return addresses, nil
}

func (md *MemoryDumper) searchRegion(memFile *os.File, region *memoryRegion, pattern []byte) []uint64 {
	var addresses []uint64

	_, err := memFile.Seek(int64(region.Start), 0)
	if err != nil {
		return addresses
	}

	buffer := make([]byte, 4096)
	var offset uint64

	for offset < region.Size {
		toRead := uint64(len(buffer))
		if remaining := region.Size - offset; remaining < toRead {
			toRead = remaining
		}

		n, err := memFile.Read(buffer[:toRead])
		if err != nil {
			break
		}

		for i := 0; i <= n-len(pattern); i++ {
			if string(buffer[i:i+len(pattern)]) == string(pattern) {
				addresses = append(addresses, region.Start+offset+uint64(i))
			}
		}

		offset += uint64(n)
	}

	return addresses
}

func (md *MemoryDumper) ReadMemoryAt(pid int, address uint64, size int) ([]byte, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, err
	}
	defer memFile.Close()

	_, err = memFile.Seek(int64(address), 0)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, size)
	n, err := memFile.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

func GetMemoryStats(pid int) map[string]interface{} {
	stats := make(map[string]interface{})

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return stats
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmSize:") {
			stats["vm_size"] = strings.TrimSpace(line[len("VmSize:"):])
		} else if strings.HasPrefix(line, "VmRSS:") {
			stats["vm_rss"] = strings.TrimSpace(line[len("VmRSS:"):])
		} else if strings.HasPrefix(line, "VmData:") {
			stats["vm_data"] = strings.TrimSpace(line[len("VmData:"):])
		} else if strings.HasPrefix(line, "VmStk:") {
			stats["vm_stack"] = strings.TrimSpace(line[len("VmStk:"):])
		} else if strings.HasPrefix(line, "VmExe:") {
			stats["vm_text"] = strings.TrimSpace(line[len("VmExe:"):])
		} else if strings.HasPrefix(line, "VmLib:") {
			stats["vm_lib"] = strings.TrimSpace(line[len("VmLib:"):])
		} else if strings.HasPrefix(line, "Threads:") {
			stats["threads"] = strings.TrimSpace(line[len("Threads:"):])
		}
	}

	statmPath := fmt.Sprintf("/proc/%d/statm", pid)
	data, err = os.ReadFile(statmPath)
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 7 {
			pageSize := uint64(4096)
			total, _ := strconv.ParseUint(fields[0], 10, 64)
			rss, _ := strconv.ParseUint(fields[1], 10, 64)
			shared, _ := strconv.ParseUint(fields[2], 10, 64)
			text, _ := strconv.ParseUint(fields[3], 10, 64)
			data, _ := strconv.ParseUint(fields[5], 10, 64)

			stats["total_pages"] = total
			stats["rss_pages"] = rss
			stats["shared_pages"] = shared
			stats["text_pages"] = text
			stats["data_pages"] = data
			stats["total_bytes"] = utils.HumanBytes(total * pageSize)
			stats["rss_bytes"] = utils.HumanBytes(rss * pageSize)
		}
	}

	return stats
}

func (md *MemoryDumper) DumpMemoryToHex(pid int, address uint64, size int) (string, error) {
	data, err := md.ReadMemoryAt(pid, address, size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

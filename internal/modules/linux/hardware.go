package linux

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// HardwareInventory collects basic hardware without osquery.
type HardwareInventory struct{}

func (m *HardwareInventory) ID() string          { return "hardware_inventory" }
func (m *HardwareInventory) Version() string     { return "1.0.0" }
func (m *HardwareInventory) Platforms() []string { return []string{"linux"} }

func (m *HardwareInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	memKB := 0
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "MemTotal:") {
				fields := strings.Fields(sc.Text())
				if len(fields) >= 2 {
					memKB, _ = strconv.Atoi(fields[1])
				}
			}
		}
		_ = f.Close()
	}
	cpuBrand := ""
	cores := 0
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") {
				_, v, ok := strings.Cut(line, ":")
				if ok && cpuBrand == "" {
					cpuBrand = strings.TrimSpace(v)
				}
			}
			if strings.HasPrefix(line, "processor") {
				cores++
			}
		}
		_ = f.Close()
	}
	hostname, _ := os.Hostname()
	value := map[string]any{
		"hostname":          hostname,
		"cpu_brand":         cpuBrand,
		"cpu_logical_cores": cores,
		"physical_memory":   int64(memKB) * 1024,
		"architecture":      runtime.GOARCH,
		"hardware_vendor":   readTrim("/sys/devices/virtual/dmi/id/sys_vendor"),
		"hardware_model":    readTrim("/sys/devices/virtual/dmi/id/product_name"),
		"hardware_serial":   readTrim("/sys/devices/virtual/dmi/id/product_serial"),
		"board_vendor":      readTrim("/sys/devices/virtual/dmi/id/board_vendor"),
		"board_model":       readTrim("/sys/devices/virtual/dmi/id/board_name"),
	}
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, nil))
	common.Finish(&res, started, "success")
	return res
}

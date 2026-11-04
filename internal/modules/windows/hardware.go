package windows

import (
	"context"
	"encoding/json"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

type HardwareInventory struct{}

func (m *HardwareInventory) ID() string          { return "hardware_inventory" }
func (m *HardwareInventory) Version() string     { return "1.0.0" }
func (m *HardwareInventory) Platforms() []string { return []string{"windows"} }

func (m *HardwareInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := `
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
[PSCustomObject]@{
  hostname = $env:COMPUTERNAME
  hardware_vendor = $cs.Manufacturer
  hardware_model = $cs.Model
  hardware_serial = $bios.SerialNumber
  cpu_brand = $cpu.Name
  cpu_physical_cores = $cpu.NumberOfCores
  cpu_logical_cores = $cpu.NumberOfLogicalProcessors
  physical_memory = [int64]$cs.TotalPhysicalMemory
} | ConvertTo-Json -Compress
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+out))
		common.Finish(&res, started, "error")
		return res
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(out), &value); err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, map[string]string{"raw_json": out}))
	common.Finish(&res, started, "success")
	return res
}

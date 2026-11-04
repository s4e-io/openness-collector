package osquerymod

import (
	"context"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/osquery"
	"github.com/s4e-io/openness-collector/internal/schema"
)

type Query struct {
	Name string
	SQL  string
}

type PackModule struct {
	ModuleID    string
	ModVersion  string
	SupportedOS []string
	Runner      *osquery.Runner
	Queries     []Query
}

func (m *PackModule) ID() string          { return m.ModuleID }
func (m *PackModule) Version() string     { return m.ModVersion }
func (m *PackModule) Platforms() []string { return m.SupportedOS }

func (m *PackModule) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	if m.Runner == nil || m.Runner.Path == "" {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "osquery not available"))
		common.Finish(&res, started, "unavailable")
		return res
	}
	for _, q := range m.Queries {
		rows, err := m.Runner.QueryJSON(ctx, q.SQL)
		if err != nil {
			res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", q.Name+": "+err.Error()))
			continue
		}
		for _, row := range rows {
			value := map[string]any{"query": q.Name}
			for k, v := range row {
				value[k] = v
			}
			res.Evidence = append(res.Evidence, common.Evidence("osquery", m.ID(), "observed", value, row))
		}
	}
	status := "success"
	if len(res.Errors) > 0 && len(res.Evidence) > 0 {
		status = "partial"
	} else if len(res.Errors) > 0 {
		status = "error"
	}
	common.Finish(&res, started, status)
	return res
}

func DefaultHardwarePack(runner *osquery.Runner) *PackModule {
	return &PackModule{
		ModuleID:    "hardware_inventory",
		ModVersion:  "1.0.0",
		SupportedOS: []string{"linux", "windows", "darwin"},
		Runner:      runner,
		Queries: []Query{
			{Name: "system_info", SQL: "SELECT hostname, cpu_brand, cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial, board_vendor, board_model FROM system_info;"},
		},
	}
}

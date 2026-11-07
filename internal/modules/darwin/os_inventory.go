package darwin

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/procutil"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// OSInventory is a minimal macOS identity probe so build hosts can run self-test.
type OSInventory struct{}

func (m *OSInventory) ID() string          { return "os_inventory" }
func (m *OSInventory) Version() string     { return "1.0.0" }
func (m *OSInventory) Platforms() []string { return []string{"darwin"} }

func (m *OSInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	hostname, _ := os.Hostname()
	productName := firstLine(ctx, "sw_vers", "-productName")
	productVersion := firstLine(ctx, "sw_vers", "-productVersion")
	buildVersion := firstLine(ctx, "sw_vers", "-buildVersion")
	kernel := firstLine(ctx, "uname", "-r")

	value := map[string]any{
		"distribution_name":    productName,
		"distribution_id":      "macos",
		"distribution_version": productVersion,
		"version_id":           productVersion,
		"pretty_name":          strings.TrimSpace(productName + " " + productVersion),
		"build_version":        buildVersion,
		"kernel_version":       kernel,
		"architecture":         runtime.GOARCH,
		"hostname":             hostname,
		"platform":             "darwin",
	}
	raw := map[string]string{
		"product_name":    productName,
		"product_version": productVersion,
		"build_version":   buildVersion,
		"uname_r":         kernel,
	}
	status := "success"
	if productName == "" && productVersion == "" {
		status = "partial"
		res.Errors = append(res.Errors, common.Err(m.ID(), "partial", "sw_vers unavailable"))
	}
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, raw))
	common.Finish(&res, started, status)
	return res
}

func firstLine(ctx context.Context, name string, args ...string) string {
	cmd := procutil.Command(ctx, name, args...)
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

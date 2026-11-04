package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/modules/darwin"
	"github.com/s4e-io/openness-collector/internal/modules/linux"
	"github.com/s4e-io/openness-collector/internal/modules/osquerymod"
	"github.com/s4e-io/openness-collector/internal/modules/swinv"
	"github.com/s4e-io/openness-collector/internal/modules/windows"
	"github.com/s4e-io/openness-collector/internal/osquery"
	"github.com/s4e-io/openness-collector/internal/schema"
)

type Options struct {
	Modules          []string
	ExcludeModules   []string
	ForceFailModules []string
	Timeout          time.Duration
	ModuleTimeout    time.Duration
	OsqueryPath      string
	KeepRawEvidence  bool
	BuildID          string
	// RegistryValues are extra HKLM values for the Windows
	// security_configuration module (collect --registry-values).
	RegistryValues []windows.RegistryValueSpec
	// FileProbes are files to check for the Windows applications they name
	// (collect --file-probes).
	FileProbes []windows.FileProbe
}

type Engine struct {
	opts    Options
	modules []common.Module
	osqVer  string
}

func New(opts Options) *Engine {
	e := &Engine{opts: opts}
	e.modules = e.buildRegistry()
	return e
}

func (e *Engine) buildRegistry() []common.Module {
	var mods []common.Module
	var runner *osquery.Runner
	if loc, err := osquery.Locate(e.opts.OsqueryPath); err == nil {
		runner = &osquery.Runner{Path: loc.Path, Timeout: e.opts.ModuleTimeout, MaxOutputBytes: 32 * 1024 * 1024}
		e.osqVer = loc.Version
	}

	switch runtime.GOOS {
	case "linux":
		mods = append(mods,
			&linux.OSInventory{},
			&linux.HardwareInventory{},
			&linux.Packages{},
			&linux.KernelInventory{},
			&linux.Services{},
			&linux.Processes{},
			&linux.ListeningPorts{},
			&linux.EvidenceChain{},
			&linux.LoadedLibraries{},
			&linux.Containers{},
			&linux.LanguageDeps{},
			&linux.SecurityConfiguration{},
			&linux.Users{},
			&linux.NetworkInventory{},
			&swinv.SoftwareInventory{},
		)
	case "windows":
		mods = append(mods,
			&windows.OSInventory{},
			&windows.HardwareInventory{},
			&windows.Applications{Probes: e.opts.FileProbes},
			&windows.WindowsFeatures{},
			&windows.CBSPackages{},
			&windows.Patches{},
			&windows.MissingUpdates{},
			&windows.LanguageDeps{},
			&windows.Services{},
			&windows.Processes{},
			&windows.ListeningPorts{},
			&windows.EvidenceChain{},
			&windows.SecurityProducts{},
			&windows.SecurityConfiguration{ExtraRegistry: e.opts.RegistryValues},
			&windows.Users{},
			&windows.NetworkInventory{},
			&swinv.SoftwareInventory{},
		)
	case "darwin":
		mods = append(mods, &darwin.OSInventory{})
		if runner != nil {
			mods = append(mods, osquerymod.DefaultHardwarePack(runner))
		}
	default:
		if runner != nil {
			mods = append(mods, osquerymod.DefaultHardwarePack(runner))
		}
	}

	return mods
}

func (e *Engine) ListModules() []common.Module {
	return e.modules
}

func (e *Engine) Run(ctx context.Context) (*schema.Document, error) {
	started := time.Now()
	if e.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.opts.Timeout)
		defer cancel()
	}

	doc := &schema.Document{
		SchemaVersion: schema.SchemaVersion,
		Collector: schema.CollectorInfo{
			Name:           schema.CollectorName,
			Version:        schema.CollectorVersion,
			BuildID:        e.opts.BuildID,
			OsqueryVersion: e.osqVer,
		},
		Collection: schema.CollectionInfo{
			CollectionID:   common.NewID(),
			StartedAt:      schema.NowUTC(),
			ExecutionMode:  "local",
			PrivilegeLevel: privilegeLevel(),
			Status:         "complete",
			Partial:        false,
		},
		Asset: schema.AssetInfo{
			AssetID:      common.NewID(),
			Hostname:     hostname(),
			Platform:     runtime.GOOS,
			Architecture: runtime.GOARCH,
		},
		Modules: []schema.ModuleResult{},
		Errors:  []schema.ErrorEntry{},
	}

	selected := e.selectedModules()
	for _, mod := range selected {
		if !common.Supports(mod.Platforms(), runtime.GOOS) {
			continue
		}
		mctx := ctx
		var cancel context.CancelFunc
		if e.opts.ModuleTimeout > 0 {
			mctx, cancel = context.WithTimeout(ctx, e.opts.ModuleTimeout)
		}
		result := mod.Run(mctx)
		if cancel != nil {
			cancel()
		}
		if e.shouldForceFail(mod.ID()) {
			result.Status = "error"
			result.Errors = append(result.Errors, common.Err(mod.ID(), "injected_failure", "forced failure for partial-proof harness"))
			result.Records = len(result.Evidence)
		}
		if !e.opts.KeepRawEvidence {
			for i := range result.Evidence {
				result.Evidence[i].RawValue = nil
			}
		}
		doc.Modules = append(doc.Modules, result)
		e.mergeModule(doc, result)
		if result.Status != "success" {
			doc.Collection.Partial = true
			doc.Errors = append(doc.Errors, result.Errors...)
		}
	}

	doc.Asset.AssetID = stableAssetID(doc.Asset, doc.Asset.AssetID)
	doc.Collection.CompletedAt = schema.NowUTC()
	doc.Collection.DurationMs = time.Since(started).Milliseconds()
	if doc.Collection.Partial {
		doc.Collection.Status = "partial"
	}
	return doc, nil
}

// stableAssetID derives the asset id from the OS machine identity
// (/etc/machine-id, MachineGuid, IOPlatformUUID) so one host keeps one id
// across collections; collection_id is the per-run id. Without a machine id
// the random id generated at start is kept, since a hostname is not unique.
func stableAssetID(a schema.AssetInfo, fallback string) string {
	mid := strings.ToLower(strings.TrimSpace(a.MachineID))
	if mid == "" {
		return fallback
	}
	sum := sha256.Sum256([]byte("openness-asset:" + a.Platform + ":" + mid))
	return hex.EncodeToString(sum[:8])
}

func (e *Engine) shouldForceFail(id string) bool {
	for _, m := range e.opts.ForceFailModules {
		if strings.TrimSpace(m) == id {
			return true
		}
	}
	return false
}

func (e *Engine) selectedModules() []common.Module {
	include := map[string]bool{}
	for _, m := range e.opts.Modules {
		include[strings.TrimSpace(m)] = true
	}
	exclude := map[string]bool{}
	for _, m := range e.opts.ExcludeModules {
		exclude[strings.TrimSpace(m)] = true
	}
	var out []common.Module
	for _, mod := range e.modules {
		if exclude[mod.ID()] {
			continue
		}
		if len(include) > 0 && !include[mod.ID()] {
			continue
		}
		out = append(out, mod)
	}
	return out
}

func (e *Engine) mergeModule(doc *schema.Document, result schema.ModuleResult) {
	values := make([]any, 0, len(result.Evidence))
	for _, ev := range result.Evidence {
		values = append(values, ev)
	}
	switch result.ModuleID {
	case "os_inventory":
		if len(result.Evidence) > 0 {
			doc.OperatingSystem = result.Evidence[0].Value
			if m, ok := result.Evidence[0].Value.(map[string]any); ok {
				if v, ok := m["fqdn"].(string); ok {
					doc.Asset.FQDN = v
				}
				if v, ok := m["machine_id"].(string); ok {
					doc.Asset.MachineID = v
				}
				if v, ok := m["hostname"].(string); ok && v != "" {
					doc.Asset.Hostname = v
				}
				if v, ok := m["privilege_level"].(string); ok && v != "" {
					doc.Collection.PrivilegeLevel = v
				}
			}
		}
	case "hardware_inventory":
		if len(result.Evidence) > 0 {
			doc.Hardware = result.Evidence[0].Value
		}
	case "network_inventory":
		doc.Network = values
	case "users":
		doc.Users = values
	case "groups":
		doc.Groups = values
	case "packages":
		doc.Packages = values
	case "applications":
		doc.Applications = values
	case "patches":
		doc.Patches = values
	case "services":
		doc.Services = values
	case "processes":
		doc.Processes = values
	case "listening_ports":
		doc.ListeningPorts = values
	case "evidence_chain":
		doc.EvidenceChains = values
	case "cbs_packages":
		doc.CBSPackages = values
	case "containers":
		doc.Containers = values
	case "language_deps":
		doc.LanguageDeps = values
	case "loaded_libraries":
		doc.LoadedLibraries = values
	case "software_inventory":
		doc.SoftwareInventory = values
	case "windows_features":
		doc.Features = values
	case "missing_updates":
		doc.MissingUpdates = values
		for _, ev := range result.Evidence {
			if m, ok := ev.Value.(map[string]any); ok {
				if t, _ := m["entity_type"].(string); t == "update_context" {
					doc.UpdateContext = m
					break
				}
			}
		}
	case "security_products":
		doc.SecurityProducts = values
	case "kernel_inventory":
		if len(result.Evidence) > 0 {
			doc.Kernel = result.Evidence[0].Value
		}
	case "security_configuration":
		if len(result.Evidence) > 0 {
			doc.SecurityConfig = result.Evidence[0].Value
		} else if len(values) > 0 {
			doc.SecurityConfig = values
		}
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func privilegeLevel() string {
	if runtime.GOOS == "windows" {
		// Refined by os_inventory evidence (admin|user). Default until then.
		return "user"
	}
	if os.Geteuid() == 0 {
		return "root"
	}
	return "user"
}

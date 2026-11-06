package schema

import (
	"time"

	"github.com/s4e-io/openness-collector/internal/version"
)

const SchemaVersion = "1.6.0"
const CollectorName = "openness"

// CollectorVersion follows internal/version (ldflags / VERSION file).
var CollectorVersion = version.SemVer()

type Document struct {
	SchemaVersion     string         `json:"schema_version"`
	Collector         CollectorInfo  `json:"collector"`
	Collection        CollectionInfo `json:"collection"`
	Asset             AssetInfo      `json:"asset"`
	OperatingSystem   any            `json:"operating_system,omitempty"`
	Hardware          any            `json:"hardware,omitempty"`
	Network           any            `json:"network,omitempty"`
	Users             []any          `json:"users,omitempty"`
	Groups            []any          `json:"groups,omitempty"`
	Packages          []any          `json:"packages,omitempty"`
	Applications      []any          `json:"applications,omitempty"`
	Patches           []any          `json:"patches,omitempty"`
	MissingUpdates    []any          `json:"missing_updates,omitempty"`
	Services          []any          `json:"services,omitempty"`
	Processes         []any          `json:"processes,omitempty"`
	ListeningPorts    []any          `json:"listening_ports,omitempty"`
	Features          []any          `json:"features,omitempty"`
	Registry          []any          `json:"registry,omitempty"`
	Files             []any          `json:"files,omitempty"`
	SecurityProducts  []any          `json:"security_products,omitempty"`
	Kernel            any            `json:"kernel,omitempty"`
	SecurityConfig    any            `json:"security_configuration,omitempty"`
	EvidenceChains    []any          `json:"evidence_chains,omitempty"`
	CBSPackages       []any          `json:"cbs_packages,omitempty"`
	UpdateContext     any            `json:"update_context,omitempty"`
	Containers        []any          `json:"containers,omitempty"`
	LanguageDeps      []any          `json:"language_deps,omitempty"`
	LoadedLibraries   []any          `json:"loaded_libraries,omitempty"`
	SoftwareInventory []any          `json:"software_inventory,omitempty"`
	Modules           []ModuleResult `json:"modules"`
	Errors            []ErrorEntry   `json:"errors"`
	Integrity         IntegrityInfo  `json:"integrity"`
}

type CollectorInfo struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	BuildID        string `json:"build_id"`
	OsqueryVersion string `json:"osquery_version"`
}

type CollectionInfo struct {
	CollectionID   string `json:"collection_id"`
	StartedAt      string `json:"started_at"`
	CompletedAt    string `json:"completed_at"`
	DurationMs     int64  `json:"duration_ms"`
	ExecutionMode  string `json:"execution_mode"`
	PrivilegeLevel string `json:"privilege_level"`
	Status         string `json:"status"`
	Partial        bool   `json:"partial"`
}

type AssetInfo struct {
	AssetID      string `json:"asset_id"`
	Hostname     string `json:"hostname"`
	FQDN         string `json:"fqdn"`
	MachineID    string `json:"machine_id"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

type EvidenceRecord struct {
	EvidenceID       string `json:"evidence_id"`
	Source           string `json:"source"`
	SourceModule     string `json:"source_module"`
	ObservedAt       string `json:"observed_at"`
	Value            any    `json:"value"`
	RawValue         any    `json:"raw_value,omitempty"`
	CollectionStatus string `json:"collection_status"`
}

type ModuleResult struct {
	ModuleID      string           `json:"module_id"`
	ModuleVersion string           `json:"module_version"`
	Status        string           `json:"status"`
	StartedAt     string           `json:"started_at"`
	CompletedAt   string           `json:"completed_at"`
	DurationMs    int64            `json:"duration_ms"`
	Records       int              `json:"records"`
	Evidence      []EvidenceRecord `json:"evidence"`
	Errors        []ErrorEntry     `json:"errors"`
	// Truncated is set when the module stopped collecting at a record or size
	// limit; the module errors carry the reason (e.g. package_limit_truncated).
	Truncated bool `json:"truncated,omitempty"`
}

type ErrorEntry struct {
	Code      string `json:"code"`
	ModuleID  string `json:"module_id,omitempty"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type IntegrityInfo struct {
	Algorithm    string `json:"algorithm"`
	PayloadHash  string `json:"payload_hash"`
	Signature    string `json:"signature"`
	SigningKeyID string `json:"signing_key_id"`
}

func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

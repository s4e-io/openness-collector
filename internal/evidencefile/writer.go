package evidencefile

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/s4e-io/openness-collector/internal/schema"
)

const MaxOutputBytes = 256 * 1024 * 1024

// maxOutputBytes is MaxOutputBytes; a variable so tests can lower it.
var maxOutputBytes int64 = MaxOutputBytes

// ErrTooLarge is returned by Write when the encoded document is over the
// size limit; nothing is written.
var ErrTooLarge = errors.New("output exceeds max size")

var (
	allowedCollectionStatus = map[string]bool{
		"complete": true,
		"partial":  true,
		"error":    true,
	}
	allowedModuleStatus = map[string]bool{
		"success":           true,
		"partial":           true,
		"error":             true,
		"unavailable":       true,
		"permission_denied": true,
	}
	allowedEvidenceStatus = map[string]bool{
		"observed":          true,
		"permission_denied": true,
		"unavailable":       true,
		"error":             true,
		"skipped":           true,
		"partial":           true,
	}
	// Schema 1.3.4+: language_deps Python entity/relationship contract.
	allowedPythonEntityTypes = map[string]bool{
		"process":                   true,
		"python_interpreter":        true,
		"python_environment":        true,
		"python_distribution":       true,
		"python_inventory_coverage": true,
		"relationship":              true,
		// Other language_deps entities remain allowed.
		"language_runtime":      true,
		"language_deps_summary": true,
		"node_application":      true,
		"node_package":          true,
		"java_application":      true,
		"java_archive":          true,
		"go_binary":             true,
		"go_module":             true,
		"nuget_package":         true,
	}
	allowedPythonRelationships = map[string]bool{
		"process_uses_python_interpreter":           true,
		"process_uses_python_environment":           true,
		"process_loads_python_distribution":         true,
		"python_environment_contains_distribution":  true,
		"python_interpreter_belongs_to_os_package":  true,
		"python_distribution_belongs_to_os_package": true,
	}
)

func Write(path string, doc *schema.Document, compress bool) (string, error) {
	sum, err := PayloadHash(doc)
	if err != nil {
		return "", err
	}
	doc.Integrity = schema.IntegrityInfo{
		Algorithm:   "SHA-256",
		PayloadHash: sum,
	}

	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	if int64(len(payload)) > maxOutputBytes {
		return "", fmt.Errorf("%w: %d", ErrTooLarge, len(payload))
	}

	data := payload
	if compress {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(payload); err != nil {
			return "", err
		}
		if err := zw.Close(); err != nil {
			return "", err
		}
		data = buf.Bytes()
		if filepath.Ext(path) == ".openness" {
			path = path + ".gz"
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".openness-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o640); err != nil {
		// best-effort on platforms without chmod semantics
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return path, nil
}

// PayloadHash computes SHA-256 hex over a JSON-canonical copy of the document
// with Integrity zeroed. Round-tripping through encoding/json ensures the hash
// matches after Load (typed `any` values become generic JSON types).
func PayloadHash(doc *schema.Document) (string, error) {
	tmpDoc := *doc
	tmpDoc.Integrity = schema.IntegrityInfo{}
	raw, err := json.Marshal(tmpDoc)
	if err != nil {
		return "", err
	}
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return "", err
	}
	hashPayload, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(hashPayload)
	return hex.EncodeToString(sum[:]), nil
}

func Load(path string) (*schema.Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(zr); err != nil {
			return nil, err
		}
		b = buf.Bytes()
	}
	var doc schema.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func ValidateBasic(doc *schema.Document) []string {
	return Validate(doc)
}

func Validate(doc *schema.Document) []string {
	var issues []string
	if doc.SchemaVersion == "" {
		issues = append(issues, "missing schema_version")
	}
	if doc.Collector.Name == "" {
		issues = append(issues, "missing collector.name")
	}
	if doc.Collection.CollectionID == "" {
		issues = append(issues, "missing collection.collection_id")
	}
	if doc.Asset.Hostname == "" {
		issues = append(issues, "missing asset.hostname")
	}
	if doc.Integrity.PayloadHash == "" {
		issues = append(issues, "missing integrity.payload_hash")
	} else {
		got, err := PayloadHash(doc)
		if err != nil {
			issues = append(issues, "integrity recompute failed: "+err.Error())
		} else if got != doc.Integrity.PayloadHash {
			issues = append(issues, "integrity.payload_hash mismatch")
		}
	}
	if doc.Integrity.Algorithm != "" && doc.Integrity.Algorithm != "SHA-256" {
		issues = append(issues, "unsupported integrity.algorithm: "+doc.Integrity.Algorithm)
	}
	if doc.Collection.Status != "" && !allowedCollectionStatus[doc.Collection.Status] {
		issues = append(issues, "unknown collection.status: "+doc.Collection.Status)
	}
	entityIDs := map[string]bool{}
	type relRef struct {
		modIdx, evIdx int
		rel           string
		src, dst      string
	}
	var rels []relRef
	for i, mod := range doc.Modules {
		if mod.Status != "" && !allowedModuleStatus[mod.Status] {
			issues = append(issues, fmt.Sprintf("module[%d] %s unknown status: %s", i, mod.ModuleID, mod.Status))
		}
		for j, ev := range mod.Evidence {
			if ev.CollectionStatus != "" && !allowedEvidenceStatus[ev.CollectionStatus] {
				issues = append(issues, fmt.Sprintf("module[%d] %s evidence[%d] unknown collection_status: %s", i, mod.ModuleID, j, ev.CollectionStatus))
			}
			if m, ok := ev.Value.(map[string]any); ok {
				if id, _ := m["entity_id"].(string); id != "" {
					entityIDs[id] = true
				}
				if et, _ := m["entity_type"].(string); et == "relationship" {
					src, _ := m["source_entity_id"].(string)
					dst, _ := m["target_entity_id"].(string)
					rel, _ := m["relationship"].(string)
					rels = append(rels, relRef{i, j, rel, src, dst})
				}
			}
			if mod.ModuleID == "language_deps" {
				issues = append(issues, validatePythonLanguageDepValue(i, j, ev.Value)...)
			}
		}
	}
	for _, r := range rels {
		if r.src != "" && !entityIDs[r.src] {
			issues = append(issues, fmt.Sprintf("module[%d] evidence[%d] relationship %s source_entity_id missing: %s", r.modIdx, r.evIdx, r.rel, r.src))
		}
		if r.dst != "" && !entityIDs[r.dst] {
			issues = append(issues, fmt.Sprintf("module[%d] evidence[%d] relationship %s target_entity_id missing: %s", r.modIdx, r.evIdx, r.rel, r.dst))
		}
	}
	return issues
}

func validatePythonLanguageDepValue(modIdx, evIdx int, value any) []string {
	m, ok := value.(map[string]any)
	if !ok {
		// json decode may yield map[string]interface{} already; also tolerate typed structs
		return nil
	}
	et, _ := m["entity_type"].(string)
	if et == "" {
		return nil
	}
	var issues []string
	if !allowedPythonEntityTypes[et] {
		issues = append(issues, fmt.Sprintf("module[%d] language_deps evidence[%d] unknown entity_type: %s", modIdx, evIdx, et))
	}
	if et == "relationship" {
		rel, _ := m["relationship"].(string)
		if rel != "" && !allowedPythonRelationships[rel] {
			// Allow non-python relationships from other language runtimes in same module.
			if strings.HasPrefix(rel, "process_uses_python_") ||
				strings.HasPrefix(rel, "python_") {
				issues = append(issues, fmt.Sprintf("module[%d] language_deps evidence[%d] unknown python relationship: %s", modIdx, evIdx, rel))
			}
		}
	}
	if et == "python_distribution" {
		// OS-package ownership fields are mandatory only for os_package origin (Linux dpkg path).
		// Filesystem / Windows site-packages distributions must still declare installation_origin
		// and may leave os_* fields null.
		if _, exists := m["installation_origin"]; !exists {
			issues = append(issues, fmt.Sprintf("module[%d] language_deps evidence[%d] python_distribution missing field installation_origin", modIdx, evIdx))
		}
		origin, _ := m["installation_origin"].(string)
		if origin == "os_package" {
			for _, key := range []string{
				"os_package_manager", "os_binary_package",
				"os_source_package", "os_package_version", "ownership_confidence",
			} {
				if _, exists := m[key]; !exists {
					issues = append(issues, fmt.Sprintf("module[%d] language_deps evidence[%d] python_distribution missing field %s", modIdx, evIdx, key))
				}
			}
		}
		if status, _ := m["runtime_load_status"].(string); status == "confirmed_loaded" {
			for _, key := range []string{
				"loaded_by_process_ids", "loaded_module_paths",
				"runtime_detection_method", "runtime_evidence_ids",
			} {
				if _, exists := m[key]; !exists {
					issues = append(issues, fmt.Sprintf("module[%d] language_deps evidence[%d] confirmed_loaded missing field %s", modIdx, evIdx, key))
				}
			}
		}
	}
	return issues
}

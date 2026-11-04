package evidencefile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/evidencefile"
	"github.com/s4e-io/openness-collector/internal/schema"
)

func sampleDoc() *schema.Document {
	return &schema.Document{
		SchemaVersion: schema.SchemaVersion,
		Collector: schema.CollectorInfo{
			Name:    schema.CollectorName,
			Version: schema.CollectorVersion,
		},
		Collection: schema.CollectionInfo{
			CollectionID:   "abc123",
			StartedAt:      "2026-07-28T00:00:00Z",
			CompletedAt:    "2026-07-28T00:00:01Z",
			ExecutionMode:  "local",
			PrivilegeLevel: "user",
			Status:         "complete",
		},
		Asset: schema.AssetInfo{
			AssetID:      "asset1",
			Hostname:     "host1",
			Platform:     "linux",
			Architecture: "arm64",
		},
		Modules: []schema.ModuleResult{
			{
				ModuleID:      "os_inventory",
				ModuleVersion: "1.0.0",
				Status:        "success",
				Evidence: []schema.EvidenceRecord{
					{EvidenceID: "e1", Source: "native", SourceModule: "os_inventory", CollectionStatus: "observed", Value: map[string]any{"ok": true}},
				},
			},
		},
		Packages: []any{
			map[string]any{
				"name":               "curl",
				"version":            "7.88.1-10+deb12u5",
				"raw_version_string": "7.88.1-10+deb12u5",
			},
		},
	}
}

func TestWriteValidateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.openness")
	doc := sampleDoc()
	out, err := evidencefile.Write(path, doc, false)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := evidencefile.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	issues := evidencefile.Validate(loaded)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
}

func TestValidateIntegrityMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.openness")
	doc := sampleDoc()
	if _, err := evidencefile.Write(path, doc, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	integ := m["integrity"].(map[string]any)
	integ["payload_hash"] = strings.Repeat("0", 64)
	corrupted, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(dir, "corrupted.openness")
	if err := os.WriteFile(badPath, corrupted, 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, err := evidencefile.Load(badPath)
	if err != nil {
		t.Fatal(err)
	}
	issues := evidencefile.Validate(loaded)
	found := false
	for _, i := range issues {
		if strings.Contains(i, "payload_hash mismatch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected hash mismatch, got %v", issues)
	}
}

func TestValidateRejectsUnknownStatus(t *testing.T) {
	doc := sampleDoc()
	doc.Collection.Status = "weird"
	sum, err := evidencefile.PayloadHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Integrity = schema.IntegrityInfo{Algorithm: "SHA-256", PayloadHash: sum}
	issues := evidencefile.Validate(doc)
	found := false
	for _, i := range issues {
		if strings.Contains(i, "unknown collection.status") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unknown status issue, got %v", issues)
	}
}

func TestValidateRelationshipReferentialIntegrity(t *testing.T) {
	doc := sampleDoc()
	doc.Modules = append(doc.Modules, schema.ModuleResult{
		ModuleID: "language_deps", ModuleVersion: "1.1.3", Status: "success",
		Evidence: []schema.EvidenceRecord{
			{EvidenceID: "p1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{"entity_type": "process", "entity_id": "process:1"}},
			{EvidenceID: "d1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{
					"entity_type": "python_distribution", "entity_id": "python:dist:1",
					"installation_origin": "os_package", "os_package_manager": "dpkg",
					"os_binary_package": "python3-mako", "os_source_package": "mako",
					"os_package_version": "1.1.3+ds1-2ubuntu0.1", "ownership_confidence": "direct",
					"runtime_load_status": "installed_not_proven_loaded",
				}},
			{EvidenceID: "r1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{
					"entity_type": "relationship", "entity_id": "rel:1",
					"relationship":     "python_distribution_belongs_to_os_package",
					"source_entity_id": "python:dist:1",
					"target_entity_id": "pkg:dpkg:python3-mako:all:1.1.3+ds1-2ubuntu0.1",
				}},
		},
	})
	doc.Modules = append(doc.Modules, schema.ModuleResult{
		ModuleID: "packages", ModuleVersion: "1.2.0", Status: "success",
		Evidence: []schema.EvidenceRecord{
			{EvidenceID: "pkg1", Source: "native", SourceModule: "packages", CollectionStatus: "observed",
				Value: map[string]any{
					"entity_type": "package",
					"entity_id":   "pkg:dpkg:python3-mako:all:1.1.3+ds1-2ubuntu0.1",
					"name":        "python3-mako",
				}},
		},
	})
	sum, err := evidencefile.PayloadHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Integrity = schema.IntegrityInfo{Algorithm: "SHA-256", PayloadHash: sum}
	if issues := evidencefile.Validate(doc); len(issues) != 0 {
		t.Fatalf("expected clean referential integrity, got %v", issues)
	}

	// Missing package entity must fail.
	doc.Modules[len(doc.Modules)-1].Evidence = nil
	sum, _ = evidencefile.PayloadHash(doc)
	doc.Integrity = schema.IntegrityInfo{Algorithm: "SHA-256", PayloadHash: sum}
	issues := evidencefile.Validate(doc)
	found := false
	for _, i := range issues {
		if strings.Contains(i, "target_entity_id missing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing target failure, got %v", issues)
	}
}

func TestPackageVersionPreservation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.openness")
	doc := sampleDoc()
	raw := "1:2.3.4-5ubuntu1~22.04.1"
	doc.Packages = []any{
		map[string]any{
			"name":               "openssl",
			"version":            raw,
			"raw_version_string": raw,
			"epoch":              "1",
		},
	}
	if _, err := evidencefile.Write(path, doc, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := evidencefile.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	pkg := loaded.Packages[0].(map[string]any)
	if pkg["version"] != raw || pkg["raw_version_string"] != raw {
		t.Fatalf("version not preserved: %+v", pkg)
	}
	blob, _ := os.ReadFile(path)
	if strings.Contains(string(blob), "Authorization") || strings.Contains(string(blob), `"api_key"`) {
		t.Fatal("secrets leaked into .openness")
	}
}

func TestValidateWindowsLanguageDepsFilesystemOrigin(t *testing.T) {
	doc := sampleDoc()
	doc.Modules = append(doc.Modules, schema.ModuleResult{
		ModuleID: "language_deps", ModuleVersion: "1.0.0", Status: "success",
		Evidence: []schema.EvidenceRecord{
			{EvidenceID: "s1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{"entity_type": "language_deps_summary", "entity_id": "lang:windows:summary"}},
			{EvidenceID: "d1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{
					"entity_type": "python_distribution", "entity_id": "lang:python:dist:pip:x",
					"installation_origin": "filesystem_site_packages",
					"name":                "pip", "version": "23.1.2",
				}},
			{EvidenceID: "g1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{
					"entity_type": "go_module", "entity_id": "lang:go:mod:example",
					"module_path": "example.com/mod", "runtime_version": nil,
				}},
			{EvidenceID: "n1", Source: "native", SourceModule: "language_deps", CollectionStatus: "observed",
				Value: map[string]any{
					"entity_type": "nuget_package", "entity_id": "lang:nuget:pkg:x:path",
					"name": "x", "version": "1",
				}},
		},
	})
	sum, err := evidencefile.PayloadHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Integrity = schema.IntegrityInfo{Algorithm: "SHA-256", PayloadHash: sum}
	if issues := evidencefile.Validate(doc); len(issues) != 0 {
		t.Fatalf("windows language_deps should validate, got %v", issues)
	}
}

// Package swinv implements the software_inventory module: a catalog-driven
// detector for products that package managers do not describe well (databases,
// web servers, runtimes, TLS libraries). It only reads files and registry keys.
// It never executes a product binary to ask for its version.
package swinv

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalog/*.yaml
var catalogFS embed.FS

// CatalogVersion is bumped when catalog entries change meaning. It is
// recorded on the summary record so a resolver knows which detection rules
// produced the evidence.
const CatalogVersion = "2026.10.1"

// Product is one catalog entry: how to notice a product on a root and where
// its version can be read without running it.
type Product struct {
	ProductKey string   `yaml:"product_key"`
	Vendor     string   `yaml:"vendor"`
	Product    string   `yaml:"product"`
	CPEPrefix  string   `yaml:"cpe_prefix"`
	Platforms  []string `yaml:"platforms"`
	// Verified records where the catalog entry was exercised against a real
	// install (image name, OS). Empty means the entry is written from vendor
	// documentation only and the README marks it as unverified.
	Verified []string `yaml:"verified"`
	Signals  Signals  `yaml:"signals"`
	Readers  []Reader `yaml:"version_readers"`
	// PatchReaders list patch identifiers next to the version (Oracle oneoffs).
	PatchReaders []Reader `yaml:"patch_readers"`
}

// Signals are presence hints. Any path, process or registry hit makes an
// instance candidate; ports only corroborate.
type Signals struct {
	// Paths are glob patterns relative to the scan root, per platform. A hit is
	// an install location candidate.
	Paths map[string][]string `yaml:"paths"`
	// ProcessNames are glob patterns matched against the executable base name.
	ProcessNames []string `yaml:"process_names"`
	// Ports are TCP listen ports commonly used by the product.
	Ports []int `yaml:"ports"`
	// Registry are Windows key globs under HKLM. A hit is an install candidate;
	// InstallPathValue names the value holding the install directory.
	Registry []RegistrySignal `yaml:"registry"`
}

// RegistrySignal is a Windows registry key glob (HKLM only).
type RegistrySignal struct {
	Key              string `yaml:"key"`
	InstallPathValue string `yaml:"install_path_value"`
}

// Reader describes one way to read a version from an install location.
type Reader struct {
	// Type is one of file_regex, zip_entry_regex, dir_names, pe_version,
	// registry_value.
	Type string `yaml:"type"`
	// Path is a glob relative to the install location. For registry_value it
	// is the key path relative to the matched registry key (may be empty).
	Path string `yaml:"path"`
	// Pattern is a regexp with one capture group (file_regex, dir_names).
	Pattern string `yaml:"pattern"`
	// Value is the registry value name (registry_value) or the archive entry
	// name (zip_entry_regex).
	Value string `yaml:"value"`
	// MaxBytes bounds how much of a file is scanned (file_regex). 0 = default.
	MaxBytes int64 `yaml:"max_bytes"`
	// Platforms restricts the reader; empty means all platforms of the product.
	Platforms []string `yaml:"platforms"`

	re *regexp.Regexp
}

type catalogFile struct {
	Products []Product `yaml:"products"`
}

// LoadCatalog parses the embedded catalog and compiles patterns. Entries are
// returned sorted by product_key so output order is deterministic.
func LoadCatalog() ([]Product, error) {
	entries, err := catalogFS.ReadDir("catalog")
	if err != nil {
		return nil, err
	}
	var products []Product
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := catalogFS.ReadFile("catalog/" + e.Name())
		if err != nil {
			return nil, err
		}
		var f catalogFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for i := range f.Products {
			p := f.Products[i]
			if err := validateProduct(&p); err != nil {
				return nil, fmt.Errorf("%s: %s: %w", e.Name(), p.ProductKey, err)
			}
			if seen[p.ProductKey] {
				return nil, fmt.Errorf("%s: duplicate product_key %s", e.Name(), p.ProductKey)
			}
			seen[p.ProductKey] = true
			products = append(products, p)
		}
	}
	sort.Slice(products, func(i, j int) bool { return products[i].ProductKey < products[j].ProductKey })
	return products, nil
}

func validateProduct(p *Product) error {
	if p.ProductKey == "" {
		return fmt.Errorf("product_key required")
	}
	if len(p.Platforms) == 0 {
		return fmt.Errorf("platforms required")
	}
	hasSignal := len(p.Signals.ProcessNames) > 0 || len(p.Signals.Registry) > 0
	for _, paths := range p.Signals.Paths {
		if len(paths) > 0 {
			hasSignal = true
		}
	}
	if !hasSignal {
		return fmt.Errorf("at least one path, process or registry signal required")
	}
	if len(p.Readers) == 0 {
		return fmt.Errorf("at least one version reader required")
	}
	for i := range p.Readers {
		if err := compileReader(&p.Readers[i]); err != nil {
			return fmt.Errorf("version_readers[%d]: %w", i, err)
		}
	}
	for i := range p.PatchReaders {
		if err := compileReader(&p.PatchReaders[i]); err != nil {
			return fmt.Errorf("patch_readers[%d]: %w", i, err)
		}
	}
	return nil
}

func compileReader(r *Reader) error {
	switch r.Type {
	case "file_regex", "dir_names", "zip_entry_regex":
		if r.Pattern == "" {
			return fmt.Errorf("%s needs pattern", r.Type)
		}
		if r.Type == "zip_entry_regex" && r.Value == "" {
			return fmt.Errorf("zip_entry_regex needs value (entry name)")
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return err
		}
		if re.NumSubexp() < 1 {
			return fmt.Errorf("%s pattern needs one capture group", r.Type)
		}
		r.re = re
		if r.Path == "" {
			return fmt.Errorf("%s needs path", r.Type)
		}
	case "pe_version":
		if r.Path == "" {
			return fmt.Errorf("pe_version needs path")
		}
	case "registry_value":
		if r.Value == "" {
			return fmt.Errorf("registry_value needs value")
		}
	default:
		return fmt.Errorf("unknown reader type %q", r.Type)
	}
	return nil
}

func (p Product) supports(goos string) bool {
	for _, pl := range p.Platforms {
		if pl == goos {
			return true
		}
	}
	return false
}

func (r Reader) supports(goos string) bool {
	if len(r.Platforms) == 0 {
		return true
	}
	for _, pl := range r.Platforms {
		if pl == goos {
			return true
		}
	}
	return false
}

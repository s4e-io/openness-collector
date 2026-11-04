package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/s4e-io/openness-collector/internal/auth"
	"github.com/s4e-io/openness-collector/internal/collect"
	"github.com/s4e-io/openness-collector/internal/config"
	"github.com/s4e-io/openness-collector/internal/evidencefile"
	"github.com/s4e-io/openness-collector/internal/modules/windows"
	"github.com/s4e-io/openness-collector/internal/schema"
	"github.com/s4e-io/openness-collector/internal/upload"
)

// BinaryName is the command name users run. The evidence field collector.name
// keeps schema.CollectorName so existing .openness consumers are not affected.
const BinaryName = "openness-collector"

var (
	outputPath    string
	configPath    string
	modulesFlag   string
	excludeFlag   string
	forceFailFlag string
	timeoutSec    int
	moduleTimeout int
	apiURL        string
	apiKeyEnv     string
	apiTokenFlag  string
	doUpload      bool
	uploadGzip    bool
	compress      bool
	logLevel      string
	fileProbes    string
	osqueryPath   string
	keepRaw       bool
	buildID       string
	allowInsecure bool
	registryVals  string
)

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   BinaryName,
		Short: "Openness local endpoint evidence collector",
	}
	root.AddCommand(newCollect())
	root.AddCommand(newValidate())
	root.AddCommand(newInspect())
	root.AddCommand(newUpload())
	root.AddCommand(newLogin())
	root.AddCommand(newLogout())
	root.AddCommand(newWhoAmI())
	root.AddCommand(newVersion())
	root.AddCommand(newModules())
	root.AddCommand(newSelfTest())
	return root
}

func newCollect() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect local endpoint evidence into a .openness file",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := collect.Options{
				Timeout:         time.Duration(timeoutSec) * time.Second,
				ModuleTimeout:   time.Duration(moduleTimeout) * time.Second,
				OsqueryPath:     osqueryPath,
				KeepRawEvidence: keepRaw,
				BuildID:         buildID,
			}
			if registryVals != "" {
				specs, err := windows.ParseRegistryValuesArg(registryVals)
				if err != nil {
					return err
				}
				opts.RegistryValues = specs
			}
			if fileProbes != "" {
				probes, err := windows.ParseFileProbesArg(fileProbes)
				if err != nil {
					return err
				}
				opts.FileProbes = probes
			}
			if modulesFlag != "" {
				opts.Modules = splitCSV(modulesFlag)
			}
			if excludeFlag != "" {
				opts.ExcludeModules = splitCSV(excludeFlag)
			}
			if forceFailFlag != "" {
				opts.ForceFailModules = splitCSV(forceFailFlag)
			}
			if configPath != "" {
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}
				if outputPath == "" {
					outputPath = cfg.Output.Path
				}
				if cfg.Collection.TimeoutSeconds > 0 && timeoutSec == 900 {
					opts.Timeout = time.Duration(cfg.Collection.TimeoutSeconds) * time.Second
				}
				if cfg.Collection.ModuleTimeoutSeconds > 0 && moduleTimeout == 120 {
					opts.ModuleTimeout = time.Duration(cfg.Collection.ModuleTimeoutSeconds) * time.Second
				}
				opts.KeepRawEvidence = opts.KeepRawEvidence || cfg.Collection.KeepRawEvidence
				if cfg.Output.Compression == "gzip" {
					compress = true
				}
				if cfg.Upload.Enabled {
					doUpload = true
					if apiURL == "" {
						apiURL = cfg.Upload.APIURL
					}
					if apiKeyEnv == "" {
						apiKeyEnv = cfg.Upload.APIKeyEnv
					}
					allowInsecure = allowInsecure || cfg.Upload.AllowInsecure
				}
				if len(opts.Modules) == 0 && len(cfg.Modules) > 0 {
					for k, v := range cfg.Modules {
						if v {
							opts.Modules = append(opts.Modules, k)
						}
					}
				}
			}
			if outputPath == "" {
				outputPath = "./host.openness"
			}

			engine := collect.New(opts)
			doc, err := engine.Run(cmd.Context())
			if err != nil {
				return err
			}
			path, err := evidencefile.Write(outputPath, doc, compress)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s status=%s modules=%d records_partial=%v duration_ms=%d\n",
				path, doc.Collection.Status, len(doc.Modules), doc.Collection.Partial, doc.Collection.DurationMs)

			if doUpload {
				key, src, err := auth.ResolveToken(apiTokenFlag, apiKeyEnv)
				if err != nil {
					return fmt.Errorf("collect succeeded but upload failed: %w", err)
				}
				if apiURL == "" {
					return fmt.Errorf("collect succeeded but upload failed: --api-url is required until the cloud ingest endpoint ships")
				}
				receipt, err := upload.UploadFile(cmd.Context(), path, upload.Options{
					APIURL:         apiURL,
					APIKey:         key,
					IdempotencyKey: doc.Collection.CollectionID,
					AllowInsecure:  allowInsecure,
					Gzip:           uploadGzip,
				})
				if err != nil {
					return fmt.Errorf("collect succeeded but upload failed: %w", err)
				}
				fmt.Fprintf(os.Stderr, "upload ok status=%d token_source=%s gzip=%v\n", receipt.StatusCode, src, uploadGzip || strings.HasSuffix(path, ".gz"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "output .openness path")
	cmd.Flags().StringVar(&configPath, "config", "", "config yaml path")
	cmd.Flags().StringVar(&modulesFlag, "modules", "", "comma-separated module allowlist")
	cmd.Flags().StringVar(&excludeFlag, "exclude-modules", "", "comma-separated module denylist")
	cmd.Flags().StringVar(&forceFailFlag, "force-fail-modules", "", "comma-separated modules to force-fail (partial-proof harness)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 900, "total collection timeout seconds")
	cmd.Flags().IntVar(&moduleTimeout, "module-timeout", 120, "per-module timeout seconds")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "optional upload API URL")
	cmd.Flags().StringVar(&apiKeyEnv, "api-key-env", "OPENNESS_API_KEY", "env var holding API key")
	cmd.Flags().StringVar(&apiTokenFlag, "token", "", "API token (overrides env/credentials)")
	cmd.Flags().BoolVar(&doUpload, "upload", false, "upload after local write")
	cmd.Flags().BoolVar(&uploadGzip, "upload-gzip", true, "gzip evidence bytes on upload (Content-Encoding: gzip)")
	cmd.Flags().BoolVar(&allowInsecure, "allow-insecure-upload", false, "allow http:// upload URLs")
	cmd.Flags().BoolVar(&compress, "compress", false, "gzip compress output file on disk")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level")
	cmd.Flags().StringVar(&osqueryPath, "osquery-path", "", "explicit osqueryi path")
	cmd.Flags().BoolVar(&keepRaw, "keep-raw-evidence", true, "keep raw_value fields")
	cmd.Flags().StringVar(&buildID, "build-id", "", "build identifier")
	cmd.Flags().StringVar(&registryVals, "registry-values", "",
		`extra HKLM values for Windows security_configuration: base64url JSON array [{"key":"SYSTEM\\...","name":"X"}] or @<file>`)
	cmd.Flags().StringVar(&fileProbes, "file-probes", "",
		`files to check for the Windows applications they name: base64url JSON array [{"id","name","publisher","path","base"}] or @<file>`)
	return cmd
}

func newValidate() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file]",
		Short: "Validate a .openness file (integrity + status enums)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := evidencefile.Load(args[0])
			if err != nil {
				return err
			}
			issues := evidencefile.Validate(doc)
			if len(issues) > 0 {
				for _, i := range issues {
					fmt.Println("FAIL:", i)
				}
				return fmt.Errorf("%d validation issues", len(issues))
			}
			fmt.Println("OK")
			return nil
		},
	}
}

func newInspect() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect [file]",
		Short: "Inspect a .openness file summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := evidencefile.Load(args[0])
			if err != nil {
				return err
			}
			summary := map[string]any{
				"schema_version":  doc.SchemaVersion,
				"hostname":        doc.Asset.Hostname,
				"fqdn":            doc.Asset.FQDN,
				"machine_id":      doc.Asset.MachineID,
				"platform":        doc.Asset.Platform,
				"privilege_level": doc.Collection.PrivilegeLevel,
				"status":          doc.Collection.Status,
				"partial":         doc.Collection.Partial,
				"modules":         len(doc.Modules),
				"packages":        len(doc.Packages),
				"applications":    len(doc.Applications),
				"services":        len(doc.Services),
				"processes":       len(doc.Processes),
				"duration_ms":     doc.Collection.DurationMs,
				"integrity":       doc.Integrity.PayloadHash,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(summary)
		},
	}
}

func newUpload() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload an existing .openness file",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, src, err := auth.ResolveToken(apiTokenFlag, apiKeyEnv)
			if err != nil {
				return err
			}
			if apiURL == "" {
				return fmt.Errorf("--api-url is required until the cloud ingest endpoint ships")
			}
			receipt, err := upload.UploadFile(cmd.Context(), path, upload.Options{
				APIURL:        apiURL,
				APIKey:        key,
				AllowInsecure: allowInsecure,
				Gzip:          uploadGzip,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "upload ok status=%d token_source=%s gzip=%v\n", receipt.StatusCode, src, uploadGzip || strings.HasSuffix(path, ".gz"))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "output", "", "path to .openness file")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "upload API URL")
	cmd.Flags().StringVar(&apiKeyEnv, "api-key-env", "OPENNESS_API_KEY", "API key env var")
	cmd.Flags().StringVar(&apiTokenFlag, "token", "", "API token (overrides env/credentials)")
	cmd.Flags().BoolVar(&uploadGzip, "upload-gzip", true, "gzip evidence bytes on upload (Content-Encoding: gzip)")
	cmd.Flags().BoolVar(&allowInsecure, "allow-insecure-upload", false, "allow http:// upload URLs")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print collector version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s %s schema=%s\n", BinaryName, schema.CollectorVersion, schema.SchemaVersion)
		},
	}
}

func newModules() *cobra.Command {
	return &cobra.Command{
		Use:   "modules",
		Short: "List available modules for this platform",
		Run: func(cmd *cobra.Command, args []string) {
			engine := collect.New(collect.Options{})
			for _, m := range engine.ListModules() {
				fmt.Printf("%s %s platforms=%s\n", m.ID(), m.Version(), strings.Join(m.Platforms(), ","))
			}
		},
	}
}

func newSelfTest() *cobra.Command {
	return &cobra.Command{
		Use:   "self-test",
		Short: "Run a quick local self-test collection",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine := collect.New(collect.Options{
				ModuleTimeout: 30 * time.Second,
				Timeout:       90 * time.Second,
			})
			available := engine.ListModules()
			opts := collect.Options{
				ModuleTimeout: 30 * time.Second,
				Timeout:       90 * time.Second,
			}
			// Prefer os_inventory when this platform has it; otherwise run every available module.
			for _, m := range available {
				if m.ID() == "os_inventory" {
					opts.Modules = []string{"os_inventory"}
					break
				}
			}
			engine = collect.New(opts)
			doc, err := engine.Run(context.Background())
			if err != nil {
				return err
			}
			if len(available) == 0 {
				return fmt.Errorf("self-test failed: no modules registered for this platform (%s)", doc.Asset.Platform)
			}
			if len(doc.Modules) == 0 {
				return fmt.Errorf("self-test failed: no modules ran")
			}
			tmp, err := os.CreateTemp("", "openness-selftest-*.openness")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			_ = tmp.Close()
			defer func() { _ = os.Remove(tmpPath) }()
			if _, err := evidencefile.Write(tmpPath, doc, false); err != nil {
				return err
			}
			loaded, err := evidencefile.Load(tmpPath)
			if err != nil {
				return err
			}
			if issues := evidencefile.Validate(loaded); len(issues) > 0 {
				return fmt.Errorf("self-test validate failed: %s", strings.Join(issues, "; "))
			}
			fmt.Printf("self-test OK platform=%s modules=%d status=%s\n", doc.Asset.Platform, len(doc.Modules), doc.Collection.Status)
			return nil
		},
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

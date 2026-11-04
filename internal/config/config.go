package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type File struct {
	ConfigVersion string `yaml:"config_version"`
	Collection    struct {
		TimeoutSeconds       int  `yaml:"timeout_seconds"`
		ModuleTimeoutSeconds int  `yaml:"module_timeout_seconds"`
		KeepRawEvidence      bool `yaml:"keep_raw_evidence"`
	} `yaml:"collection"`
	Modules map[string]bool `yaml:"modules"`
	Output  struct {
		Path        string `yaml:"path"`
		Compression string `yaml:"compression"`
	} `yaml:"output"`
	Upload struct {
		Enabled           bool   `yaml:"enabled"`
		APIURL            string `yaml:"api_url"`
		APIKeyEnv         string `yaml:"api_key_env"`
		PreserveLocalFile bool   `yaml:"preserve_local_file"`
		AllowInsecure     bool   `yaml:"allow_insecure_upload"`
	} `yaml:"upload"`
}

func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg File
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

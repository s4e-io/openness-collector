package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultTokenPage = "https://app.s4e.io/api-token"
	DefaultCheckURL  = "https://api.s4e.io/api/auth/check"
	configDirEnv     = "OPENNESS_CONFIG_DIR"
)

// Credentials is the local login store (KISS: paste API token from app).
type Credentials struct {
	Token     string `json:"token"`
	SavedAt   string `json:"saved_at"`
	Source    string `json:"source,omitempty"`
	CheckURL  string `json:"check_url,omitempty"`
	TokenPage string `json:"token_page,omitempty"`
}

func ConfigDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv(configDirEnv)); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "openness"), nil
}

func CredentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func Save(creds Credentials) error {
	path, err := CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if creds.SavedAt == "" {
		creds.SavedAt = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Load() (*Credentials, error) {
	path, err := CredentialsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var creds Credentials
	if err := json.Unmarshal(b, &creds); err != nil {
		return nil, err
	}
	creds.Token = strings.TrimSpace(creds.Token)
	if creds.Token == "" {
		return nil, fmt.Errorf("credentials file has empty token")
	}
	return &creds, nil
}

func Delete() error {
	path, err := CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ResolveToken order: explicit flag > envName > OPENNESS_API_KEY > S4E_API_TOKEN > saved credentials.
// Prefer env or credentials over --token (tokens on argv appear in process lists / shell history).
func ResolveToken(explicit, envName string) (string, string, error) {
	if t := strings.TrimSpace(explicit); t != "" {
		return t, "flag", nil
	}
	candidates := []string{}
	if envName != "" {
		candidates = append(candidates, envName)
	}
	for _, n := range []string{"OPENNESS_API_KEY", "S4E_API_TOKEN"} {
		dup := false
		for _, c := range candidates {
			if c == n {
				dup = true
				break
			}
		}
		if !dup {
			candidates = append(candidates, n)
		}
	}
	for _, n := range candidates {
		if t := strings.TrimSpace(os.Getenv(n)); t != "" {
			return t, "env:" + n, nil
		}
	}
	creds, err := Load()
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("not logged in (run: openness-collector login)")
		}
		return "", "", err
	}
	return creds.Token, "credentials", nil
}

type CheckResult struct {
	OK         bool
	StatusCode int
	Message    string
	RawBody    string
}

// CheckToken validates a public API token via api.s4e.io auth/check (JSON body "token").
func CheckToken(ctx context.Context, checkURL, token string) (*CheckResult, error) {
	if checkURL == "" {
		checkURL = DefaultCheckURL
	}
	u, err := url.Parse(checkURL)
	if err != nil {
		return nil, fmt.Errorf("token check URL must be HTTPS or loopback HTTP without credentials")
	}
	loopbackHTTP := u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if (u.Scheme != "https" && !loopbackHTTP) || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("token check URL must be HTTPS or loopback HTTP without credentials")
	}
	token = strings.TrimSpace(token)
	if len(token) < 32 {
		return nil, fmt.Errorf("token looks too short")
	}
	payload, _ := json.Marshal(map[string]any{"token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "openness-collector")
	// A 307/308 can replay the JSON body containing the token to another host.
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	out := &CheckResult{StatusCode: resp.StatusCode, RawBody: string(body)}
	// S4E public API often returns HTTP 200 with JSON {"code":401|200,...}.
	var parsed struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Error   bool   `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	apiCode := parsed.Code
	if apiCode == 0 {
		apiCode = resp.StatusCode
	}
	out.Message = strings.TrimSpace(parsed.Message)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && apiCode >= 200 && apiCode < 300 {
		out.OK = true
		if out.Message == "" {
			out.Message = "token valid"
		}
		return out, nil
	}
	if out.Message == "" {
		out.Message = fmt.Sprintf("auth check failed http=%d api_code=%d", resp.StatusCode, apiCode)
	}
	return out, nil
}

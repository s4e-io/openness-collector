package osquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/procutil"
)

type Runner struct {
	Path           string
	ExpectedSHA256 string
	Timeout        time.Duration
	MaxOutputBytes int64
}

type LocateResult struct {
	Path    string
	Version string
	Source  string // bundled | side-by-side | system
}

func Locate(explicit string) (LocateResult, error) {
	if explicit != "" {
		ver, err := versionOf(explicit)
		if err != nil {
			return LocateResult{}, err
		}
		return LocateResult{Path: explicit, Version: ver, Source: "explicit"}, nil
	}

	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, "osquery", osqueryBinaryName()),
			filepath.Join(dir, osqueryBinaryName()),
		}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				ver, err := versionOf(c)
				if err == nil {
					return LocateResult{Path: c, Version: ver, Source: "side-by-side"}, nil
				}
			}
		}
	}

	if p, err := exec.LookPath(osqueryBinaryName()); err == nil {
		ver, err := versionOf(p)
		if err == nil {
			return LocateResult{Path: p, Version: ver, Source: "system"}, nil
		}
	}
	return LocateResult{}, fmt.Errorf("osquery not found")
}

func osqueryBinaryName() string {
	if runtime.GOOS == "windows" {
		return "osqueryi.exe"
	}
	return "osqueryi"
}

func versionOf(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := procutil.Command(ctx, path, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *Runner) VerifyChecksum() error {
	if r.ExpectedSHA256 == "" {
		return nil
	}
	f, err := os.Open(r.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(sum, r.ExpectedSHA256) {
		return fmt.Errorf("osquery checksum mismatch: got %s want %s", sum, r.ExpectedSHA256)
	}
	return nil
}

func (r *Runner) QueryJSON(ctx context.Context, sql string) ([]map[string]string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := procutil.Command(qctx, r.Path, "--json", sql)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if r.MaxOutputBytes > 0 && int64(len(out)) > r.MaxOutputBytes {
		return nil, fmt.Errorf("osquery output too large: %d bytes", len(out))
	}
	var rows []map[string]string
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

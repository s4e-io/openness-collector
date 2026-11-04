package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	rePassArg = regexp.MustCompile(`(?i)--?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth|connection[_-]?string)(?:=|\s+)\S+`)
	reConnStr = regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis|amqp|https?)://[^\s]*:[^\s/]+@[^\s]+`)
	reBearer  = regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)\S+`)
)

// RedactSecrets masks common secret patterns in command lines.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = rePassArg.ReplaceAllStringFunc(s, func(m string) string {
		if i := strings.IndexAny(m, "= \t"); i >= 0 {
			return m[:i+1] + "***REDACTED***"
		}
		return "***REDACTED***"
	})
	s = reConnStr.ReplaceAllString(s, "***REDACTED_CONN***")
	s = reBearer.ReplaceAllString(s, "${1}***REDACTED***")
	return s
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return strings.TrimSpace(stringify(v))
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(t))
		return i
	default:
		return 0
	}
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1"
	case float64:
		return t != 0
	default:
		return false
	}
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Expand %SystemRoot% style is done in PowerShell; here just clean quotes.
	p = strings.Trim(p, `"'`)
	return filepath.Clean(p)
}

func parseImagePath(raw string) (binPath string, args string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if strings.HasPrefix(raw, `"`) {
		if i := strings.Index(raw[1:], `"`); i >= 0 {
			binPath = raw[1 : i+1]
			args = strings.TrimSpace(raw[i+2:])
			return binPath, args
		}
	}
	parts := strings.SplitN(raw, " ", 2)
	binPath = parts[0]
	if len(parts) > 1 {
		args = parts[1]
	}
	return binPath, args
}

func svchostGroupFromArgs(args string) string {
	fields := strings.Fields(args)
	for i := 0; i < len(fields)-1; i++ {
		if strings.EqualFold(fields[i], "-k") {
			return fields[i+1]
		}
	}
	return ""
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func decodeJSONRows(out string) ([]map[string]any, error) {
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return nil, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		var one map[string]any
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil, err
		}
		return []map[string]any{one}, nil
	}
	return rows, nil
}

func entitySocket(proto, addr string, port int) string {
	return "sock:" + proto + ":" + addr + ":" + strconv.Itoa(port)
}

func entityProcess(pid int) string {
	return "process:" + strconv.Itoa(pid)
}

func entityBinary(path string) string {
	return "bin:" + strings.ToLower(filepath.Clean(path))
}

func entityService(name string) string {
	return "service:" + strings.ToLower(name)
}

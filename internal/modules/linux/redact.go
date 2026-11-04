package linux

import (
	"regexp"
	"strings"
)

var (
	rePassArg = regexp.MustCompile(`(?i)--?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth)(?:=|\s+)\S+`)
	reConnStr = regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis|amqp|https?)://[^\s]*:[^\s/]+@[^\s]+`)
	reBearer  = regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)\S+`)
)

// RedactSecrets masks common secret patterns in command lines / config snippets.
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

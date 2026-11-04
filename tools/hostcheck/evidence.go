package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// values returns the "value" object of every evidence record in list.
func values(list []any) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, it := range list {
		rec, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if v, ok := rec["value"].(map[string]any); ok {
			out = append(out, v)
		}
	}
	return out
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// str returns m[key] as a string; nil and missing are "".
func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func num(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

// setDiff returns the keys in a that are not in b, sorted.
func setDiff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sample(list []string, n int) string {
	if len(list) <= n {
		return strings.Join(list, ", ")
	}
	return strings.Join(list[:n], ", ") + fmt.Sprintf(" (+%d more)", len(list)-n)
}

// normArch maps uname/PROCESSOR_ARCHITECTURE names to GOARCH names.
func normArch(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "x86_64", "amd64", "x64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i686", "x86":
		return "386"
	}
	return strings.ToLower(strings.TrimSpace(a))
}

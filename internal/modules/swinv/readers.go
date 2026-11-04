package swinv

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultMaxScanBytes = 256 << 20 // product binaries can be large (oracle ~400MB)
	scanChunk           = 1 << 20
	scanOverlap         = 512
	maxGlobMatches      = 64
)

// versionHit is one value a reader found, with where it came from so the
// resolver can judge it.
type versionHit struct {
	Source string `json:"source"` // reader type
	Path   string `json:"path"`   // file or registry path read
	Value  string `json:"value"`
}

// fileRegexFirst scans a file in bounded chunks and returns the first capture
// of the pattern. Scanning stops at maxBytes. Binary content is fine.
func fileRegexFirst(path string, r *Reader) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	limit := r.MaxBytes
	if limit <= 0 {
		limit = defaultMaxScanBytes
	}
	rd := bufio.NewReaderSize(io.LimitReader(f, limit), scanChunk)
	buf := make([]byte, 0, scanChunk+scanOverlap)
	chunk := make([]byte, scanChunk)
	for {
		n, err := rd.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if m := r.re.FindSubmatch(buf); m != nil && len(m) > 1 {
				return string(m[1]), true
			}
			if len(buf) > scanOverlap {
				buf = append(buf[:0], buf[len(buf)-scanOverlap:]...)
			}
		}
		if err != nil {
			return "", false
		}
	}
}

// fileRegexAll returns every distinct capture in a (small) text file, in
// order of first appearance. Used for patch lists.
func fileRegexAll(path string, r *Reader) []string {
	limit := r.MaxBytes
	if limit <= 0 {
		limit = 8 << 20
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range r.re.FindAllSubmatch(b, -1) {
		v := string(m[1])
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// dirNames matches the pattern against the base names of entries under a
// glob and returns the captures (sorted). Used for Oracle oneoff patch dirs.
func dirNames(globPath string, r *Reader) []string {
	matches, _ := filepath.Glob(globPath)
	var out []string
	seen := map[string]bool{}
	for _, m := range matches {
		base := filepath.Base(m)
		if sm := r.re.FindStringSubmatch(base); sm != nil && len(sm) > 1 && !seen[sm[1]] {
			seen[sm[1]] = true
			out = append(out, sm[1])
		}
		if len(out) >= maxGlobMatches {
			break
		}
	}
	sort.Strings(out)
	return out
}

// globUnder expands a pattern relative to a base directory. Absolute patterns
// are still joined under base so container roots stay sealed.
func globUnder(base, pattern string) []string {
	pattern = strings.TrimLeft(pattern, `/\`)
	matches, err := filepath.Glob(filepath.Join(base, pattern))
	if err != nil || len(matches) == 0 {
		return nil
	}
	if len(matches) > maxGlobMatches {
		matches = matches[:maxGlobMatches]
	}
	sort.Strings(matches)
	return matches
}

func existsDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

package linux

import (
	"bufio"
	"io"
	"strings"
)

// apkPackage is one stanza of an apk installed database
// (/lib/apk/db/installed). Only the fields the collector emits are kept.
type apkPackage struct {
	Name    string // P:
	Version string // V: full apk version, e.g. 1.2.5-r1
	Arch    string // A:
	Origin  string // o: source (origin) package name, may be empty
}

// parseAPKDB parses an apk installed database. Stanzas are separated by blank
// lines; each line is a single-letter key, a colon and the value. CRLF line
// endings and trailing whitespace are tolerated. A limit > 0 stops parsing
// after that many packages.
func parseAPKDB(r io.Reader, limit int) ([]apkPackage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []apkPackage
	var cur apkPackage
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = apkPackage{}
	}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if line == "" {
			flush()
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := strings.TrimSpace(line[2:])
		switch line[0] {
		case 'P':
			cur.Name = v
		case 'V':
			cur.Version = v
		case 'A':
			cur.Arch = v
		case 'o':
			cur.Origin = v
		}
	}
	flush()
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, sc.Err()
}

// splitAPKVersion splits "1.2.5-r1" into version "1.2.5" and release "r1".
// A version without a -rN suffix is returned unchanged with an empty release.
func splitAPKVersion(raw string) (version, release string) {
	i := strings.LastIndex(raw, "-r")
	if i <= 0 || i+2 >= len(raw) {
		return raw, ""
	}
	for _, c := range raw[i+2:] {
		if c < '0' || c > '9' {
			return raw, ""
		}
	}
	return raw[:i], raw[i+1:]
}

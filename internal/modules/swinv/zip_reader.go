package swinv

import (
	"archive/zip"
	"io"
)

// zipEntryRegexFirst opens a zip/jar and applies the reader pattern to one
// entry (for example Tomcat's ServerInfo.properties inside catalina.jar).
func zipEntryRegexFirst(path, entry string, r *Reader) (string, bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", false
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != entry {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", false
		}
		b, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if err != nil {
			return "", false
		}
		if m := r.re.FindSubmatch(b); m != nil && len(m) > 1 {
			return string(m[1]), true
		}
		return "", false
	}
	return "", false
}

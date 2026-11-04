package linux

import (
	"archive/zip"
	"bufio"
	"io"
	"strings"
)

func readZipManifestAndPom(path string) (map[string]string, map[string]string) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil
	}
	defer r.Close()

	manifest := map[string]string{}
	pom := map[string]string{}
	for _, f := range r.File {
		name := f.Name
		if name == "META-INF/MANIFEST.MF" {
			manifest = parseManifestMF(readZipFileLimited(f, 64<<10))
		}
		if strings.HasSuffix(name, "/pom.properties") && strings.Contains(name, "META-INF/maven/") {
			pom = parseJavaProperties(readZipFileLimited(f, 16<<10))
		}
	}
	if len(manifest) == 0 {
		manifest = nil
	}
	if len(pom) == 0 {
		pom = nil
	}
	return manifest, pom
}

func listZipSuffix(path, suffix string, limit int) []string {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()
	var out []string
	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), suffix) {
			out = append(out, f.Name)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func readZipFileLimited(f *zip.File, limit int64) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return ""
	}
	return string(b)
}

func parseManifestMF(s string) map[string]string {
	out := map[string]string{}
	var key string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, " ") && key != "" {
			out[key] += strings.TrimPrefix(line, " ")
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			key = strings.TrimSpace(line[:i])
			out[key] = strings.TrimSpace(line[i+1:])
		}
	}
	return out
}

func parseJavaProperties(s string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return out
}

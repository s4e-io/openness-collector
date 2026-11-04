package linux

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// Processes collects from /proc (not ps).
func (m *Processes) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	entries, err := os.ReadDir("/proc")
	if err != nil {
		code := "collection_error"
		status := "error"
		if os.IsPermission(err) {
			code = "PROC_PERMISSION_DENIED"
			status = "permission_denied"
		}
		res.Errors = append(res.Errors, common.Err(m.ID(), code, err.Error()))
		common.Finish(&res, started, status)
		return res
	}

	denied := 0
	raced := 0
	for _, e := range entries {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "process scan cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		rec, status, errCode := readProcess(pid)
		switch status {
		case "observed":
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
		case "permission_denied":
			denied++
		case "race":
			raced++
			res.Errors = append(res.Errors, common.Err(m.ID(), errCode, "pid="+e.Name()))
		}
	}
	if denied > 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "PROC_PERMISSION_DENIED", "some pids inaccessible count="+strconv.Itoa(denied)))
	}
	status := "success"
	if denied > 0 || raced > 0 {
		status = "partial"
	}
	if len(res.Evidence) == 0 && denied > 0 {
		status = "permission_denied"
	}
	common.Finish(&res, started, status)
	return res
}

func readProcess(pid int) (map[string]any, string, string) {
	base := "/proc/" + strconv.Itoa(pid)
	cmdlineB, err := os.ReadFile(base + "/cmdline")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "race", "PROC_RACE_DISAPPEARED"
		}
		if os.IsPermission(err) {
			return nil, "permission_denied", "PROC_PERMISSION_DENIED"
		}
		return nil, "race", "PROC_RACE_DISAPPEARED"
	}
	cmdline := RedactSecrets(strings.ReplaceAll(string(cmdlineB), "\x00", " "))
	cmdline = strings.TrimSpace(cmdline)

	name := ""
	ppid := 0
	uid := 0
	gid := 0
	if st, err := os.ReadFile(base + "/status"); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			switch {
			case strings.HasPrefix(line, "Name:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "PPid:"):
				ppid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			case strings.HasPrefix(line, "Uid:"):
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
				if len(fields) > 0 {
					uid, _ = strconv.Atoi(fields[0])
				}
			case strings.HasPrefix(line, "Gid:"):
				fields := strings.Fields(strings.TrimPrefix(line, "Gid:"))
				if len(fields) > 0 {
					gid, _ = strconv.Atoi(fields[0])
				}
			}
		}
	}

	exePath := ""
	exeReal := ""
	deleted := false
	if link, err := os.Readlink(base + "/exe"); err == nil {
		exePath = link
		if strings.HasSuffix(link, " (deleted)") {
			deleted = true
			exePath = strings.TrimSuffix(link, " (deleted)")
		}
		if rp, err := filepath.EvalSymlinks(exePath); err == nil {
			exeReal = rp
		} else {
			exeReal = exePath
		}
	}

	cwd := ""
	if link, err := os.Readlink(base + "/cwd"); err == nil {
		cwd = link
	}

	rec := map[string]any{
		"entity_id":           "proc:" + strconv.Itoa(pid),
		"entity_type":         "process",
		"pid":                 pid,
		"ppid":                ppid,
		"name":                name,
		"command_line":        cmdline,
		"executable_path":     nullIfEmpty(exePath),
		"executable_realpath": nullIfEmpty(exeReal),
		"executable_deleted":  deleted,
		"cwd":                 nullIfEmpty(cwd),
		"uid":                 uid,
		"gid":                 gid,
		"relationships":       []map[string]any{},
	}
	if exeReal != "" {
		rec["relationships"] = []map[string]any{{
			"type":             "process_executed_binary",
			"target_entity_id": "bin:" + exeReal,
			"confidence":       "direct",
			"evidence_source":  "/proc/pid/exe",
		}}
	}
	return rec, "observed", ""
}

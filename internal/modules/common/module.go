package common

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/s4e-io/openness-collector/internal/schema"
)

type Module interface {
	ID() string
	Version() string
	Platforms() []string
	Run(ctx context.Context) schema.ModuleResult
}

func NewResult(id, version string) schema.ModuleResult {
	now := schema.NowUTC()
	return schema.ModuleResult{
		ModuleID:      id,
		ModuleVersion: version,
		Status:        "success",
		StartedAt:     now,
		CompletedAt:   now,
		Evidence:      []schema.EvidenceRecord{},
		Errors:        []schema.ErrorEntry{},
	}
}

func Finish(res *schema.ModuleResult, started time.Time, status string) {
	res.CompletedAt = schema.NowUTC()
	res.DurationMs = time.Since(started).Milliseconds()
	res.Status = status
	res.Records = len(res.Evidence)
}

func Evidence(source, moduleID, status string, value, raw any) schema.EvidenceRecord {
	return schema.EvidenceRecord{
		EvidenceID:       NewID(),
		Source:           source,
		SourceModule:     moduleID,
		ObservedAt:       schema.NowUTC(),
		Value:            value,
		RawValue:         raw,
		CollectionStatus: status,
	}
}

func Err(moduleID, code, msg string) schema.ErrorEntry {
	return schema.ErrorEntry{
		Code:      code,
		ModuleID:  moduleID,
		Message:   msg,
		Timestamp: schema.NowUTC(),
	}
}

func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func Supports(platforms []string, current string) bool {
	for _, p := range platforms {
		if p == current || p == "all" {
			return true
		}
	}
	return false
}

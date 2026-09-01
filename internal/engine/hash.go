package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

type HashBlocklistChecker interface {
	LookupHash(sha256 string) (verdict, source string, found bool)
}

type HashEngine struct {
	blocklist HashBlocklistChecker
}

func NewHashEngine(blocklist HashBlocklistChecker) *HashEngine {
	return &HashEngine{blocklist: blocklist}
}

func (e *HashEngine) Name() string {
	return "Hash Lookup"
}

func (e *HashEngine) Weight() float64 {
	return 0.35
}

func (e *HashEngine) Scan(ctx context.Context, filepath string) (EngineResult, error) {
	start := time.Now()

	f, err := os.Open(filepath)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Cannot open file: %v", err)}},
			Duration: time.Since(start),
		}, nil
	}
	defer f.Close()

	hasher := sha256.New()

	if _, err := io.Copy(hasher, f); err != nil {
		return EngineResult{
			Status:   StatusError,
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Read error: %v", err)}},
			Duration: time.Since(start),
		}, nil
	}

	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	result := EngineResult{
		Status: StatusClean,
		Duration: time.Since(start),
	}

	if e.blocklist != nil {
		if verdict, source, found := e.blocklist.LookupHash(sha256Hash); found {
			result.Status = StatusMalicious
			result.Confidence = 0.95
			result.Findings = append(result.Findings, Finding{
				Engine:      e.Name(),
				Rule:        "BLOCKLIST_MATCH",
				Description: fmt.Sprintf("Hash matches known %s entry (source: %s)", verdict, source),
				Severity:    0.95,
			})
		}
	}

	return result, nil
}

package orchestrator

import (
	"context"
	"sync"

	"github.com/calypso-scanner/calypso/internal/engine"
)

type ScanRequest struct {
	FilePath string
	Engines  []engine.ScanEngine
}

type EngineStatus struct {
	Name   string
	Weight float64
	Status string
	Result *engine.EngineResult
	Error  error
}

type ScanResult struct {
	FilePath   string
	Verdict    string
	Score      float64
	Engines    []EngineStatus
	Findings   []engine.Finding
}

type ProgressFunc func(status EngineStatus)

type Orchestrator struct{}

func New() *Orchestrator {
	return &Orchestrator{}
}

func (o *Orchestrator) Scan(ctx context.Context, req ScanRequest, onProgress ProgressFunc) ScanResult {
	result := ScanResult{
		FilePath: req.FilePath,
		Verdict:  "clean",
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	engineResults := make([]EngineStatus, len(req.Engines))

	for i, eng := range req.Engines {
		wg.Add(1)
		go func(idx int, e engine.ScanEngine) {
			defer wg.Done()

			weight := e.Weight()

			mu.Lock()
			engineResults[idx] = EngineStatus{Name: e.Name(), Weight: weight, Status: "running"}
			mu.Unlock()

			if onProgress != nil {
				onProgress(engineResults[idx])
			}

			res, err := e.Scan(ctx, req.FilePath)

			mu.Lock()
			engineResults[idx] = EngineStatus{
				Name:   e.Name(),
				Weight: weight,
				Status: res.Status.String(),
				Result: &res,
				Error:  err,
			}
			mu.Unlock()

			if onProgress != nil {
				onProgress(engineResults[idx])
			}
		}(i, eng)
	}

	wg.Wait()

	result.Engines = engineResults

	for _, es := range engineResults {
		if es.Result != nil && es.Error == nil {
			for _, f := range es.Result.Findings {
				f.Engine = es.Name
				result.Findings = append(result.Findings, f)
			}
		}
	}

	result.Score = o.normalizeScore(result)
	result.Verdict = o.scoreToVerdict(result.Score)

	return result
}

func (o *Orchestrator) normalizeScore(result ScanResult) float64 {
	var weightedSum float64
	var weightSum float64

	for _, es := range result.Engines {
		if es.Result == nil {
			continue
		}

		badness := 0.0
		switch es.Result.Status {
		case engine.StatusMalicious:
			badness = es.Result.Confidence
		case engine.StatusSuspicious:
			badness = es.Result.Confidence * 0.5
		case engine.StatusClean:
			badness = 0
		default:
			// error / skipped / unknown engines do not contribute to the score.
			continue
		}

		weightedSum += es.Weight * badness
		weightSum += es.Weight
	}

	if weightSum == 0 {
		return 0
	}

	score := (weightedSum / weightSum) * 100
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return score
}

func (o *Orchestrator) scoreToVerdict(score float64) string {
	switch {
	case score >= 66:
		return "malicious"
	case score >= 21:
		return "suspicious"
	default:
		return "clean"
	}
}

package engine

import (
	"context"
	"time"
)

type Status int

const (
	StatusClean     Status = iota
	StatusSuspicious
	StatusMalicious
	StatusError
	StatusSkipped
)

func (s Status) String() string {
	switch s {
	case StatusClean:
		return "clean"
	case StatusSuspicious:
		return "suspicious"
	case StatusMalicious:
		return "malicious"
	case StatusError:
		return "error"
	case StatusSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

func (s Status) Emoji() string {
	switch s {
	case StatusClean:
		return "✓"
	case StatusSuspicious:
		return "!"
	case StatusMalicious:
		return "✗"
	case StatusError:
		return "⚠"
	case StatusSkipped:
		return "○"
	default:
		return "?"
	}
}

type Finding struct {
	Engine      string
	Rule        string
	Description string
	Severity    float64
	Reference   string
}

type ScanEngine interface {
	Name() string
	Scan(ctx context.Context, filepath string) (EngineResult, error)
	Weight() float64
}

type EngineResult struct {
	Status     Status
	Confidence float64
	Findings   []Finding
	Duration   time.Duration
}

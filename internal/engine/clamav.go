package engine

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type ClamAVEngine struct {
	useDaemon bool
	socket    string
}

func NewClamAVEngine() *ClamAVEngine {
	return &ClamAVEngine{
		useDaemon: false,
		socket:    "/var/run/clamd.sock",
	}
}

func (e *ClamAVEngine) Name() string {
	return "ClamAV Signatures"
}

func (e *ClamAVEngine) Weight() float64 {
	return 0.40
}

func (e *ClamAVEngine) Available() bool {
	_, err := exec.LookPath("clamscan")
	return err == nil
}

func (e *ClamAVEngine) Scan(ctx context.Context, filepath string) (EngineResult, error) {
	start := time.Now()

	if !e.Available() {
		return EngineResult{
			Status:   StatusSkipped,
			Duration: time.Since(start),
			Findings: []Finding{{
				Engine:      e.Name(),
				Description: "clamscan not found in PATH — skipping",
			}},
		}, nil
	}

	cmd := exec.CommandContext(ctx, "clamscan", "--no-summary", "--infected", filepath)
	output, err := cmd.CombinedOutput()

	result := EngineResult{
		Status:   StatusClean,
		Duration: time.Since(start),
	}

	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			result.Status = StatusMalicious
			result.Confidence = 0.9

			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, ":") && !strings.HasSuffix(line, "OK") {
					parts := strings.SplitN(line, ": ", 2)
					sigName := "UNKNOWN"
					if len(parts) > 1 {
						sigName = parts[1]
					}
					result.Findings = append(result.Findings, Finding{
						Engine:      e.Name(),
						Rule:        sigName,
						Description: fmt.Sprintf("Signature match: %s", line),
						Severity:    0.9,
					})
				}
			}
		} else if ok && exitErr.ExitCode() == 2 {
			result.Status = StatusError
			result.Findings = append(result.Findings, Finding{
				Engine:      e.Name(),
				Description: fmt.Sprintf("ClamAV error: %s", strings.TrimSpace(string(output))),
			})
		}
	}

	return result, nil
}

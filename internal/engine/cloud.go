package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	pathutil "path/filepath"
	"time"
)

type CloudEngine struct {
	apiKey string
	client *http.Client
}

func NewCloudEngine(apiKey string) *CloudEngine {
	return &CloudEngine{
		apiKey: apiKey,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (e *CloudEngine) Name() string {
	return "Cloud Analysis (VT)"
}

func (e *CloudEngine) Weight() float64 {
	return 0.50
}

type vtStats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
}

type vtResult struct {
	Category  string `json:"category"`
	Detection string `json:"result"`
}

type vtFileReport struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats   vtStats            `json:"last_analysis_stats"`
			LastAnalysisResults map[string]vtResult `json:"last_analysis_results"`
		} `json:"attributes"`
	} `json:"data"`
}

type vtAnalysisResponse struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			Status  string            `json:"status"`
			Stats   vtStats           `json:"stats"`
			Results map[string]vtResult `json:"results"`
		} `json:"attributes"`
	} `json:"data"`
}

func (e *CloudEngine) Scan(ctx context.Context, filepath string) (EngineResult, error) {
	start := time.Now()

	if e.apiKey == "" {
		return EngineResult{
			Status:   StatusSkipped,
			Duration: time.Since(start),
			Findings: []Finding{{
				Engine:      e.Name(),
				Description: "No VirusTotal API key configured — skipping cloud analysis",
			}},
		}, nil
	}

	sha256Hash, err := hashFileSHA256(filepath)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Cannot hash file: %v", err)}},
		}, nil
	}

	// 1) Look up the file by hash first. This is cheap and covers the common
	// case where VT has already analyzed the file.
	known, report, err := e.lookup(ctx, sha256Hash)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("VT API error: %v", err)}},
		}, nil
	}
	if known {
		stats := report.Data.Attributes.LastAnalysisStats
		results := report.Data.Attributes.LastAnalysisResults
		return e.buildResult(stats, results, start), nil
	}

	// 2) Hash not known to VT — fall back to a full upload and poll the
	// analysis until it completes.
	analysisID, err := e.upload(ctx, filepath)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("VT upload error: %v", err)}},
		}, nil
	}

	return e.poll(ctx, analysisID, start)
}

// lookup queries GET /api/v3/files/{sha256}. It returns (known=false, ...) when
// the file is not yet in VT's database (HTTP 404).
func (e *CloudEngine) lookup(ctx context.Context, sha256Hash string) (bool, vtFileReport, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.virustotal.com/api/v3/files/"+sha256Hash, nil)
	if err != nil {
		return false, vtFileReport{}, err
	}
	req.Header.Set("x-apikey", e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return false, vtFileReport{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, vtFileReport{}, err
	}

	if resp.StatusCode == 404 {
		return false, vtFileReport{}, nil
	}
	if resp.StatusCode != 200 {
		return false, vtFileReport{}, fmt.Errorf("VT returned status %d: %s", resp.StatusCode, string(body))
	}

	var report vtFileReport
	if err := json.Unmarshal(body, &report); err != nil {
		return false, vtFileReport{}, fmt.Errorf("failed to parse VT file report: %w", err)
	}

	return true, report, nil
}

// upload sends the file as a multipart/form-data request to POST /api/v3/files
// and returns the analysis id to poll.
func (e *CloudEngine) upload(ctx context.Context, filepath string) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	f, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	part, err := mw.CreateFormFile("file", pathutil.Base(filepath))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://www.virustotal.com/api/v3/files", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-apikey", e.apiKey)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("VT returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse VT upload response: %w", err)
	}
	if parsed.Data.ID == "" {
		return "", fmt.Errorf("VT upload response missing analysis id")
	}

	return parsed.Data.ID, nil
}

// poll waits for GET /api/v3/analyses/{id} to reach status "completed".
func (e *CloudEngine) poll(ctx context.Context, analysisID string, start time.Time) (EngineResult, error) {
	const (
		pollInterval = 3 * time.Second
		pollTimeout  = 120 * time.Second
	)

	for {
		if time.Since(start) > pollTimeout {
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: "Timed out waiting for VT analysis"}},
			}, nil
		}

		select {
		case <-ctx.Done():
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: "VT analysis cancelled"}},
			}, nil
		case <-time.After(pollInterval):
		}

		req, err := http.NewRequestWithContext(ctx, "GET", "https://www.virustotal.com/api/v3/analyses/"+analysisID, nil)
		if err != nil {
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("VT API error: %v", err)}},
			}, nil
		}
		req.Header.Set("x-apikey", e.apiKey)

		resp, err := e.client.Do(req)
		if err != nil {
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("VT API error: %v", err)}},
			}, nil
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: "Failed to read VT analysis response"}},
			}, nil
		}

		if resp.StatusCode != 200 {
			continue
		}

		var parsed vtAnalysisResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: "Failed to parse VT analysis response"}},
			}, nil
		}

		switch parsed.Data.Attributes.Status {
		case "completed":
			return e.buildResult(parsed.Data.Attributes.Stats, parsed.Data.Attributes.Results, start), nil
		case "failed":
			return EngineResult{
				Status:   StatusError,
				Duration: time.Since(start),
				Findings: []Finding{{Engine: e.Name(), Description: "VT analysis failed"}},
			}, nil
		}
	}
}

func (e *CloudEngine) buildResult(stats vtStats, results map[string]vtResult, start time.Time) EngineResult {
	total := stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected + stats.Timeout

	result := EngineResult{
		Status:   StatusClean,
		Duration: time.Since(start),
	}

	if total == 0 {
		return result
	}

	detectionRatio := float64(stats.Malicious) / float64(total)
	result.Confidence = detectionRatio

	if stats.Malicious > 0 {
		result.Status = StatusMalicious
		for engine, res := range results {
			if res.Detection != "" && res.Detection != "Clean" {
				result.Findings = append(result.Findings, Finding{
					Engine:      e.Name(),
					Rule:        fmt.Sprintf("VT_%s", engine),
					Description: fmt.Sprintf("%s detects: %s", engine, res.Detection),
					Severity:    detectionRatio,
				})
			}
		}
	} else if stats.Suspicious > 0 {
		result.Status = StatusSuspicious
	}

	return result
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

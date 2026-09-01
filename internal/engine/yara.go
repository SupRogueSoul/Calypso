package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type YaraEngine struct {
	rulesPath string
}

func NewYaraEngine(rulesPath string) *YaraEngine {
	return &YaraEngine{rulesPath: rulesPath}
}

func (e *YaraEngine) Name() string {
	return "YARA Rules"
}

func (e *YaraEngine) Weight() float64 {
	return 0.30
}

func (e *YaraEngine) Available() bool {
	entries, err := os.ReadDir(e.rulesPath)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yar") {
			return true
		}
	}
	subdirs := []string{"community", "custom"}
	for _, sub := range subdirs {
		subPath := filepath.Join(e.rulesPath, sub)
		sentries, err := os.ReadDir(subPath)
		if err != nil {
			continue
		}
		for _, se := range sentries {
			if !se.IsDir() && strings.HasSuffix(se.Name(), ".yar") {
				return true
			}
		}
	}
	return false
}

func (e *YaraEngine) Scan(ctx context.Context, filepath string) (EngineResult, error) {
	start := time.Now()

	if !e.Available() {
		return EngineResult{
			Status:   StatusSkipped,
			Duration: time.Since(start),
			Findings: []Finding{{
				Engine:      e.Name(),
				Description: "No YARA rules found — skipping",
			}},
		}, nil
	}

	f, err := os.Open(filepath)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Cannot open file: %v", err)}},
		}, nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
		}, nil
	}

	if info.Size() > 100*1024*1024 {
		return EngineResult{
			Status:   StatusSkipped,
			Duration: time.Since(start),
			Findings: []Finding{{Engine: e.Name(), Description: "File too large for YARA scan (>100MB)"}},
		}, nil
	}

	data, err := os.ReadFile(filepath)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
		}, nil
	}

	result := EngineResult{
		Status:   StatusClean,
		Duration: time.Since(start),
	}

	findings := e.scanWithBasicRules(data)
	result.Findings = findings

	if len(findings) > 0 {
		maxSeverity := 0.0
		for _, f := range findings {
			if f.Severity > maxSeverity {
				maxSeverity = f.Severity
			}
		}
		result.Confidence = maxSeverity
		if maxSeverity >= 0.8 {
			result.Status = StatusMalicious
		} else if maxSeverity >= 0.4 {
			result.Status = StatusSuspicious
		}
	}

	return result, nil
}

func (e *YaraEngine) scanWithBasicRules(data []byte) []Finding {
	var findings []Finding
	content := string(data)

	type rule struct {
		name         string
		patterns     []string
		bytePatterns [][]byte
		minHits      int
		severity     float64
		desc         string
	}

	rules := []rule{
		{
			name:     "POWERSHELL_OBFUSCATED",
			patterns: []string{"FromBase64String", "Invoke-Expression", "-enc ", "IEX(", "[System.Net.WebClient]"},
			severity: 0.7,
			desc:     "Obfuscated PowerShell detected — potential dropper/stager",
		},
		{
			name:     "MACRO_DROPPER",
			patterns: []string{"Auto_Open", "Document_Open", "Workbook_Open", "AutoOpen", "AutoClose", "Shell(", "CreateObject("},
			severity: 0.8,
			desc:     "Office macro with auto-execution and shell capabilities — likely dropper",
		},
		{
			name:     "PE_PACKER_SIGNS",
			patterns: []string{"UPX0", "UPX1", ".aspack", ".adata", "MEW", "FSG!", "PECompact"},
			severity: 0.5,
			desc:     "Packed executable detected — common in malware to evade detection",
		},
		{
			name:     "SUSPICIOUS_JS",
			patterns: []string{"eval(String.fromCharCode", "unescape(", "document.write(", "ActiveXObject", "WScript.Shell"},
			severity: 0.7,
			desc:     "Suspicious JavaScript with obfuscation and ActiveX — potential malware",
		},
		{
			name:     "RANSOMWARE_INDICATORS",
			patterns: []string{".onion", "bitcoin", "BTC", "AES-256", "decrypt", "ransom", "pay", "hours", "wallet", "encrypt", "restore", "locked"},
			minHits:  5,
			severity: 0.6,
			desc:     "Potential ransomware indicators found in file content",
		},
		{
			name:         "SHELLCODE_PATTERNS",
			patterns:     []string{"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"},
			bytePatterns: [][]byte{{0x90, 0x90, 0x90}},
			severity:     0.85,
			desc:         "Shellcode / process injection patterns detected",
		},
		{
			name:     "NETWORK_BEACON",
			patterns: []string{"cmd.exe /c", "/bin/sh -c", "certutil", "bitsadmin", "powershell -nop", "mshta"},
			severity: 0.65,
			desc:     "Suspicious network/download command patterns — possible C2 beacon",
		},
		{
			name:     "CREDENTIAL_ACCESS",
			patterns: []string{"mimikatz", "sekurlsa", "LogonPasswords", "lsass", "SAM", "SYSTEM\\CurrentControlSet"},
			severity: 0.9,
			desc:     "Credential dumping tool signatures detected",
		},
	}

	for _, r := range rules {
		hits := 0
		for _, p := range r.patterns {
			if strings.Contains(content, p) {
				hits++
			}
		}
		for _, bp := range r.bytePatterns {
			if bytes.Contains(data, bp) {
				hits++
			}
		}

		totalPatterns := len(r.patterns) + len(r.bytePatterns)
		if totalPatterns == 0 {
			continue
		}

		threshold := r.minHits
		if threshold <= 0 {
			threshold = 1
		}
		if hits >= threshold {
			ratio := float64(hits) / float64(totalPatterns)
			sev := r.severity * (0.5 + 0.5*ratio)
			findings = append(findings, Finding{
				Engine:      "YARA Rules",
				Rule:        r.name,
				Description: r.desc,
				Severity:    sev,
			})
		}
	}

	return findings
}

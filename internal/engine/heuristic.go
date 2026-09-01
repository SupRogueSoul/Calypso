package engine

import (
	"context"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

type HeuristicEngine struct{}

func NewHeuristicEngine() *HeuristicEngine {
	return &HeuristicEngine{}
}

func (e *HeuristicEngine) Name() string {
	return "Heuristic Analysis"
}

func (e *HeuristicEngine) Weight() float64 {
	return 0.25
}

func (e *HeuristicEngine) Scan(ctx context.Context, path string) (EngineResult, error) {
	start := time.Now()

	data, err := os.ReadFile(path)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Duration: time.Since(start),
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Cannot read file: %v", err)}},
		}, nil
	}

	result := EngineResult{
		Status:   StatusClean,
		Duration: time.Since(start),
	}

	if len(data) < 2 {
		return result, nil
	}

	entropy := shannonEntropy(data)
	ext := strings.ToLower(path)
	isPDF := strings.HasSuffix(ext, ".pdf") || strings.HasSuffix(ext, ".doc") || strings.HasSuffix(ext, ".docx") ||
		strings.HasSuffix(ext, ".xls") || strings.HasSuffix(ext, ".xlsx")

	entropyThreshold := 7.2
	entropySeverity := 0.6
	if isPDF {
		entropyThreshold = 8.05
		entropySeverity = 0.2
	}

	if entropy > entropyThreshold {
		result.Findings = append(result.Findings, Finding{
			Engine:      e.Name(),
			Rule:        "HIGH_ENTROPY",
			Description: fmt.Sprintf("Very high entropy (%.2f) — file likely packed, encrypted, or compressed", entropy),
			Severity:    entropySeverity,
		})
		if result.Confidence < entropySeverity {
			result.Confidence = entropySeverity
		}
	}

	if isPE(data) {
		peFindings := e.analyzePE(path, data)
		result.Findings = append(result.Findings, peFindings...)
	} else if isELF(data) {
		elfFindings := e.analyzeELF(path, data)
		result.Findings = append(result.Findings, elfFindings...)
	}

	if isOfficeDocument(data) {
		officeFindings := e.analyzeOffice(path, data)
		result.Findings = append(result.Findings, officeFindings...)
	}

	if isArchive(data) {
		archiveFindings := e.analyzeArchive(path, data)
		result.Findings = append(result.Findings, archiveFindings...)
	}

	maxSev := 0.0
	for _, f := range result.Findings {
		if f.Severity > maxSev {
			maxSev = f.Severity
		}
	}
	if maxSev > result.Confidence {
		result.Confidence = maxSev
	}

	if result.Confidence >= 0.7 {
		result.Status = StatusMalicious
	} else if result.Confidence >= 0.4 {
		result.Status = StatusSuspicious
	}

	return result, nil
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	size := float64(len(data))
	entropy := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / size
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func isPE(data []byte) bool {
	return len(data) >= 2 && data[0] == 'M' && data[1] == 'Z'
}

func isELF(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}

func isOfficeDocument(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
		return true
	}
	if data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0 {
		return true
	}
	return false
}

func isArchive(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if data[0] == 0x50 && data[1] == 0x4B {
		return true
	}
	if data[0] == 0x1F && data[1] == 0x8B {
		return true
	}
	if data[0] == '7' && data[1] == 'z' && data[2] == 0xBC && data[3] == 0xAF {
		return true
	}
	if data[0] == 'R' && data[1] == 'a' && data[2] == 'r' && data[3] == '!' {
		return true
	}
	return false
}

func (e *HeuristicEngine) analyzePE(path string, data []byte) []Finding {
	var findings []Finding

	f, err := pe.Open(path)
	if err != nil {
		return findings
	}
	defer f.Close()

	suspiciousImports := []string{
		"VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
		"CreateRemoteThread", "NtUnmapViewOfSection", "IsDebuggerPresent",
		"URLDownloadToFile", "WinExec", "ShellExecute",
		"InternetOpenA", "HttpSendRequest", "CryptEncrypt",
	}

	symbols, err := f.ImportedSymbols()
	if err == nil {
		for _, imp := range symbols {
			for _, susp := range suspiciousImports {
				if strings.Contains(imp, susp) {
					findings = append(findings, Finding{
						Engine:      e.Name(),
						Rule:        "SUSPICIOUS_IMPORT",
						Description: fmt.Sprintf("Suspicious API import: %s — commonly used in malware", susp),
						Severity:    0.5,
					})
				}
			}
		}
	}

	for _, sect := range f.Sections {
		sectData, err := sect.Data()
		if err != nil || len(sectData) == 0 {
			continue
		}
		sectEntropy := shannonEntropy(sectData)
		if sectEntropy > 7.5 && sect.Size > 1024 {
			findings = append(findings, Finding{
				Engine:      e.Name(),
				Rule:        "PACKED_SECTION",
				Description: fmt.Sprintf("Section '%s' has very high entropy (%.2f) — likely packed", sect.Name, sectEntropy),
				Severity:    0.5,
			})
		}
	}

	if f.FileHeader.TimeDateStamp == 0 {
		findings = append(findings, Finding{
			Engine:      e.Name(),
			Rule:        "TIMESTAMP_STRIPPED",
			Description: "PE timestamp is zero — common anti-analysis technique",
			Severity:    0.3,
		})
	}

	return findings
}

func (e *HeuristicEngine) analyzeELF(path string, data []byte) []Finding {
	var findings []Finding

	f, err := elf.Open(path)
	if err != nil {
		return findings
	}
	defer f.Close()

	suspiciousSymbols := []string{
		"ptrace", "dlopen", "dlsym", "mprotect",
		"socket", "connect", "execve", "/bin/sh",
	}

	symbols, err := f.Symbols()
	if err == nil {
		for _, sym := range symbols {
			for _, susp := range suspiciousSymbols {
				if strings.Contains(sym.Name, susp) {
					findings = append(findings, Finding{
						Engine:      e.Name(),
						Rule:        "SUSPICIOUS_ELF_SYMBOL",
						Description: fmt.Sprintf("Suspicious ELF symbol: %s", sym.Name),
						Severity:    0.4,
					})
				}
			}
		}
	}

	return findings
}

func (e *HeuristicEngine) analyzeOffice(path string, data []byte) []Finding {
	var findings []Finding
	content := string(data)

	macroIndicators := []string{
		"VBAProject", "Module1", "Auto_Open", "Document_Open",
		"Workbook_Open", "AutoOpen", "ThisDocument",
		"Shell(", "CreateObject(", "WScript", "PowerShell",
	}

	hits := 0
	for _, indicator := range macroIndicators {
		if strings.Contains(content, indicator) {
			hits++
		}
	}

	if hits >= 2 {
		findings = append(findings, Finding{
			Engine:      e.Name(),
			Rule:        "VBA_MACRO_DETECTED",
			Description: fmt.Sprintf("Office document contains VBA macro code (%d indicators found) — potential macro dropper", hits),
			Severity:    0.7,
		})
	}

	return findings
}

func (e *HeuristicEngine) analyzeArchive(path string, data []byte) []Finding {
	var findings []Finding

	if len(data) < 30 {
		return findings
	}

	if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
		if len(data) >= 30 {
			compressedSize := binary.LittleEndian.Uint32(data[18:22])
			uncompressedSize := binary.LittleEndian.Uint32(data[22:26])

			if uncompressedSize > 0 && compressedSize > 0 {
				ratio := float64(uncompressedSize) / float64(compressedSize)
				if ratio > 100 {
					findings = append(findings, Finding{
						Engine:      e.Name(),
						Rule:        "ARCHIVE_BOMB",
						Description: fmt.Sprintf("Potential archive bomb: compression ratio %.0fx (%d bytes -> %d bytes)", ratio, compressedSize, uncompressedSize),
						Severity:    0.7,
					})
				}
			}
		}
	}

	return findings
}

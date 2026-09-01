package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h2non/filetype"
	"github.com/h2non/filetype/types"
)

var extensionMIMEMap = map[string]string{
	".pdf":  "application/pdf",
	".doc":  "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls":  "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt":  "application/vnd.ms-powerpoint",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".exe":  "application/x-dosexec",
	".dll":  "application/x-dosexec",
	".elf":  "application/x-elf",
	".zip":  "application/zip",
	".rar":  "application/x-rar-compressed",
	".7z":   "application/x-7z-compressed",
	".tar":  "application/x-tar",
	".gz":   "application/gzip",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".mp3":  "audio/mpeg",
	".mp4":  "video/mp4",
	".js":   "application/javascript",
	".py":   "text/x-python",
	".sh":   "text/x-shellscript",
	".bat":  "text/x-msdos-batch",
	".ps1":  "text/plain",
	".vbs":  "text/vbscript",
}

var dangerousTypes = map[string]string{
	"application/x-dosexec":    "PE executable",
	"application/x-elf":        "ELF executable",
	"application/x-sharedlib":  "shared library",
	"application/x-executable": "executable",
}

type FileTypeEngine struct{}

func NewFileTypeEngine() *FileTypeEngine {
	return &FileTypeEngine{}
}

func (e *FileTypeEngine) Name() string {
	return "File Type Check"
}

func (e *FileTypeEngine) Weight() float64 {
	return 0.15
}

func (e *FileTypeEngine) Scan(ctx context.Context, path string) (EngineResult, error) {
	start := time.Now()

	f, err := os.Open(path)
	if err != nil {
		return EngineResult{
			Status:   StatusError,
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Cannot open file: %v", err)}},
			Duration: time.Since(start),
		}, nil
	}
	defer f.Close()

	buf := make([]byte, 261)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return EngineResult{
			Status:   StatusError,
			Findings: []Finding{{Engine: e.Name(), Description: fmt.Sprintf("Read error: %v", err)}},
			Duration: time.Since(start),
		}, nil
	}
	buf = buf[:n]

	kind, _ := filetype.Match(buf)
	ext := strings.ToLower(filepath.Ext(path))

	result := EngineResult{
		Status:   StatusClean,
		Duration: time.Since(start),
	}

	if kind != types.Unknown {
		expectedMIME, hasExtMIME := extensionMIMEMap[ext]
		if hasExtMIME && kind.MIME.Value != expectedMIME {
			result.Status = StatusSuspicious
			result.Confidence = 0.6
			result.Findings = append(result.Findings, Finding{
				Engine:      e.Name(),
				Rule:        "MIME_MISMATCH",
				Description: fmt.Sprintf("Extension %s suggests %s, but file is actually %s (%s)", ext, expectedMIME, kind.MIME.Value, kind.MIME.Subtype),
				Severity:    0.6,
			})
		}

		if dangerDesc, ok := dangerousTypes[kind.MIME.Value]; ok {
			fileOnly := filepath.Base(path)
			extLower := strings.ToLower(fileOnly)
			isExpectedExt := strings.HasSuffix(extLower, ".exe") || strings.HasSuffix(extLower, ".dll") ||
				strings.HasSuffix(extLower, ".elf") || strings.HasSuffix(extLower, ".so")

			if !isExpectedExt {
				result.Status = StatusSuspicious
				if result.Confidence < 0.5 {
					result.Confidence = 0.5
				}
				result.Findings = append(result.Findings, Finding{
					Engine:      e.Name(),
					Rule:        "DANGEROUS_TYPE_HIDDEN",
					Description: fmt.Sprintf("File is a %s but has non-executable extension", dangerDesc),
					Severity:    0.5,
				})
			}
		}
	}

	return result, nil
}

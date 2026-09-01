package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type engineState struct {
	Name     string
	Status   string
	Duration string
}

type ScanModel struct {
	engines    []engineState
	progress   progress.Model
	spinner    spinner.Model
	width      int
	verdict    string
	score      float64
	findings   []FindingDisplay
	done       bool
	filePath   string
	idx        int
	quarantine bool
}

type FindingDisplay struct {
	Engine      string
	Rule        string
	Description string
	Severity    float64
}

type EngineUpdateMsg struct {
	Name     string
	Status   string
	Duration string
}

type ScanCompleteMsg struct {
	Verdict  string
	Score    float64
	Findings []FindingDisplay
}

var waveSpinner spinner.Spinner

func init() {
	waveSpinner = spinner.Spinner{
		Frames: []string{"◐", "◓", "◑", "◒", "◐", "◓", "◑", "◒"},
		FPS:    80e6,
	}
}

func NewScanModel(filePath string, engineNames []string) ScanModel {
	engines := make([]engineState, len(engineNames))
	for i, name := range engineNames {
		engines[i] = engineState{Name: name, Status: "queued"}
	}

	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
		progress.WithoutPercentage(),
	)

	s := spinner.New()
	s.Spinner = waveSpinner
	s.Style = SpinnerStyle

	return ScanModel{
		engines:  engines,
		progress: p,
		spinner:  s,
		filePath: filePath,
	}
}

func (m ScanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick)
}

func (m ScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			if m.done {
				return m, tea.Quit
			}
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		p, cmd := m.progress.Update(msg)
		m.progress = p.(progress.Model)
		return m, cmd

	case EngineUpdateMsg:
		for i, e := range m.engines {
			if e.Name == msg.Name {
				m.engines[i].Status = msg.Status
				m.engines[i].Duration = msg.Duration
				break
			}
		}
		completed := 0
		for _, e := range m.engines {
			if e.Status != "queued" && e.Status != "running" {
				completed++
			}
		}
		cmd := m.progress.SetPercent(float64(completed) / float64(len(m.engines)))
		return m, cmd

	case ScanCompleteMsg:
		m.verdict = msg.Verdict
		m.score = msg.Score
		m.findings = msg.Findings
		m.done = true
		return m, nil
	}

	return m, nil
}

func (m ScanModel) View() string {
	var b strings.Builder

	logo := m.renderLogo()
	b.WriteString(logo)
	b.WriteString("\n")

	fileDisplay := m.filePath
	if len(fileDisplay) > 60 {
		fileDisplay = "..." + fileDisplay[len(fileDisplay)-57:]
	}
	b.WriteString(SubtleStyle.Render(fmt.Sprintf("  Scanning: %s", fileDisplay)))
	b.WriteString("\n\n")

	for _, e := range m.engines {
		b.WriteString(m.renderEngineRow(e))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(m.progress.ViewAs(m.progress.Percent()))
	b.WriteString("\n")

	if m.done {
		b.WriteString("\n")
		b.WriteString(m.renderVerdict())
		b.WriteString("\n")
		b.WriteString(m.renderFindings())
		b.WriteString("\n")
		b.WriteString(ActionStyle.Render("  Press Enter to exit"))
		b.WriteString("\n")
	}

	return b.String()
}

func (m ScanModel) renderLogo() string {
	logo := `
   ___  __  ______  ______  ______
  / __\/  \/    _ \/    _ \/    _ \
 / / / /\/ /  / / /  / / / /  / / /
/ /_/ / / /  / /_/  / /_/ /  / / /_
\____/ /_/  /_____/_____ /__/ /___/
      v0.1.0 — Defend before you open.`

	gradient := lipgloss.NewStyle().
		Foreground(lipgloss.Color(ColorTeal)).
		Bold(true)

	lines := strings.Split(logo, "\n")
	var styled []string
	for _, line := range lines {
		styled = append(styled, gradient.Render(line))
	}
	return strings.Join(styled, "\n")
}

func (m ScanModel) renderEngineRow(e engineState) string {
	var statusIcon string
	var statusStyle lipgloss.Style

	switch e.Status {
	case "queued":
		statusIcon = "○"
		statusStyle = StatusQueued
	case "running":
		statusIcon = m.spinner.View()
		statusStyle = StatusRunning
	case "clean":
		statusIcon = "✓"
		statusStyle = StatusDone
	case "suspicious":
		statusIcon = "!"
		statusStyle = StatusError
	case "malicious":
		statusIcon = "✗"
		statusStyle = StatusError
	case "error":
		statusIcon = "⚠"
		statusStyle = StatusError
	case "skipped":
		statusIcon = "○"
		statusStyle = StatusQueued
	default:
		statusIcon = "?"
		statusStyle = StatusQueued
	}

	name := EngineNameStyle.Render(e.Name)
	status := statusStyle.Render(statusIcon + " " + e.Status)

	var duration string
	if e.Duration != "" {
		duration = SubtleStyle.Render(fmt.Sprintf("  (%s)", e.Duration))
	}

	return fmt.Sprintf("  %s  %-12s%s%s", name, status, duration, "")
}

func (m ScanModel) renderVerdict() string {
	var style lipgloss.Style
	var label string

	switch m.verdict {
	case "clean":
		style = VerdictClean
		label = "  ✓ CLEAN  "
	case "suspicious":
		style = VerdictSuspicious
		label = "  ! SUSPICIOUS  "
	case "malicious":
		style = VerdictMalicious
		label = "  ✗ MALICIOUS  "
	default:
		style = VerdictClean
		label = "  ? UNKNOWN  "
	}

	badge := style.Render(label)
	score := SubtleStyle.Render(fmt.Sprintf("  Score: %.0f/100", m.score))

	return lipgloss.JoinHorizontal(lipgloss.Center, badge, score)
}

func (m ScanModel) renderFindings() string {
	if len(m.findings) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(BoxStyle.Render("Findings:"))
	b.WriteString("\n")

	for _, f := range m.findings {
		rule := FindingRuleStyle.Render(f.Rule)
		desc := FindingDescStyle.Render(f.Description)
		severity := SubtleStyle.Render(fmt.Sprintf(" [%.0f%%]", f.Severity*100))
		b.WriteString(FindingStyle.Render(fmt.Sprintf("  %s %s%s", rule, desc, severity)))
		b.WriteString("\n")
	}

	return b.String()
}

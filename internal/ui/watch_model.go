package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type WatchEntry struct {
	Timestamp time.Time
	FilePath  string
	Verdict   string
	Score     float64
}

type WatchModel struct {
	table    table.Model
	entries  []WatchEntry
	spinner  spinner.Model
	dir      string
	width    int
	height   int
	eventMsg string
}

func NewWatchModel(dir string, width, height int) WatchModel {
	columns := []table.Column{
		{Title: "Time", Width: 10},
		{Title: "File", Width: 40},
		{Title: "Verdict", Width: 12},
		{Title: "Score", Width: 8},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithHeight(height-6),
		table.WithWidth(width-4),
	)

	s := spinner.New()
	s.Spinner = waveSpinner
	s.Style = SpinnerStyle

	return WatchModel{
		table:   t,
		spinner: s,
		dir:     dir,
		width:   width,
		height:  height,
	}
}

type WatchScanResultMsg struct {
	Entry WatchEntry
}

type WatchEventMsg struct {
	Message string
}

func (m WatchModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick)
}

func (m WatchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case WatchScanResultMsg:
		m.entries = append([]WatchEntry{msg.Entry}, m.entries...)
		rows := make([]table.Row, 0, len(m.entries))
		for _, e := range m.entries[:min(len(m.entries), m.height-6)] {
			verdict := e.Verdict
			switch verdict {
			case "malicious":
				verdict = FailStyle.Render(verdict)
			case "suspicious":
				verdict = WarnStyle.Render(verdict)
			case "clean":
				verdict = SuccessStyle.Render(verdict)
			}
			rows = append(rows, table.Row{
				e.Timestamp.Format("15:04:05"),
				truncate(e.FilePath, 40),
				verdict,
				fmt.Sprintf("%.0f", e.Score),
			})
		}
		m.table.SetRows(rows)
		return m, nil

	case WatchEventMsg:
		m.eventMsg = msg.Message
		return m, nil
	}

	return m, nil
}

func (m WatchModel) View() string {
	var b strings.Builder

	header := TitleStyle.Render("CALYPSO WATCH") + "  " + SubtleStyle.Render(m.dir)
	b.WriteString(header)
	b.WriteString("\n\n")

	b.WriteString(m.table.View())
	b.WriteString("\n")

	if m.eventMsg != "" {
		b.WriteString(SubtleStyle.Render(m.eventMsg))
	} else {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("%s Watching for new files...", m.spinner.View())))
	}
	b.WriteString("\n")
	b.WriteString(SubtleStyle.Render("  Press q to quit"))
	b.WriteString("\n")

	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return "..." + s[len(s)-maxLen+3:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

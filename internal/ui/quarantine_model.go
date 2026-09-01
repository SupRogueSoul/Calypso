package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

type QuarantineItem struct {
	ID           int64
	OriginalPath string
	FileName     string
	Verdict      string
	Score        float64
}

func (q QuarantineItem) FilterValue() string { return q.FileName }

func (q QuarantineItem) Title() string {
	return fmt.Sprintf("%s (%.0f%%)", q.FileName, q.Score)
}

func (q QuarantineItem) Description() string {
	return q.OriginalPath
}

type QuarantineModel struct {
	list     list.Model
	selected *QuarantineItem
	choice   string
	quitting bool
}

func NewQuarantineModel(items []QuarantineItem) QuarantineModel {
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Quarantined Files"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.Styles.Title = TitleStyle
	l.Styles.PaginationStyle = SubtleStyle
	l.Styles.HelpStyle = SubtleStyle

	return QuarantineModel{
		list: l,
	}
}

type QuarantineSelectMsg struct {
	Item QuarantineItem
}

type QuarantineChoiceMsg string

func (m QuarantineModel) Init() tea.Cmd {
	return nil
}

func (m QuarantineModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(QuarantineItem); ok {
				m.selected = &i
				return m, nil
			}
		}
	case QuarantineChoiceMsg:
		m.choice = string(msg)
		return m, tea.Quit
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m QuarantineModel) View() string {
	if m.quitting {
		return ""
	}

	if m.selected != nil {
		return m.renderChoice()
	}

	return m.list.View()
}

func (m QuarantineModel) renderChoice() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n  What would you like to do with %s?\n\n",
		FindingRuleStyle.Render(m.selected.FileName)))

	choices := []string{"Restore", "Delete permanently", "Cancel"}
	for i, c := range choices {
		b.WriteString(fmt.Sprintf("  %s\n", ActionStyle.Render(fmt.Sprintf("[%d] %s", i+1, c))))
	}

	b.WriteString("\n")
	return b.String()
}

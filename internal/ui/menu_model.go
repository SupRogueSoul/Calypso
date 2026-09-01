package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type MenuItem struct {
	Name        string
	Description string
}

type MainMenuModel struct {
	choice     int
	pathInput  textinput.Model
	spinner    spinner.Model
	width      int
	height     int
	submitted  bool
	action     string
	path       string
	quitting   bool
	inputMode  bool
}

var menuItems = []MenuItem{
	{Name: "Scan", Description: "Scan a file or directory for threats"},
	{Name: "Watch", Description: "Monitor a directory in real-time"},
	{Name: "History", Description: "View past scan results"},
	{Name: "Quarantine", Description: "Manage quarantined files"},
	{Name: "Update", Description: "Refresh ClamAV + YARA signatures"},
	{Name: "Doctor", Description: "Check system health & dependencies"},
	{Name: "Config", Description: "View or edit configuration"},
}

func NewMainMenuModel() MainMenuModel {
	ti := textinput.New()
	ti.Placeholder = "Enter path..."
	ti.CharLimit = 512
	ti.Width = 50

	s := spinner.New()
	s.Spinner = spinner.Spinner{
		Frames: []string{"◐", "◓", "◑", "◒"},
		FPS:    80e6,
	}
	s.Style = SpinnerStyle

	return MainMenuModel{
		pathInput: ti,
		spinner:   s,
	}
}

type MenuActionMsg struct {
	Action string
	Path   string
}

func (m MainMenuModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m MainMenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "up", "k":
			if !m.inputMode {
				if m.choice > 0 {
					m.choice--
				}
			}
			return m, nil

		case "down", "j":
			if !m.inputMode {
				if m.choice < len(menuItems)-1 {
					m.choice++
				}
			}
			return m, nil

		case "enter":
			if m.inputMode {
				m.path = strings.TrimSpace(m.pathInput.Value())
				if m.path == "" {
					return m, nil
				}
				m.submitted = true
				m.action = menuItems[m.choice].Name
				return m, tea.Quit
			}

			selected := menuItems[m.choice].Name
			switch selected {
			case "Scan", "Watch":
				m.inputMode = true
				m.pathInput.Focus()
				return m, textinput.Blink
			default:
				m.submitted = true
				m.action = selected
				return m, tea.Quit
			}

		case "esc":
			if m.inputMode {
				m.inputMode = false
				m.pathInput.Blur()
				return m, nil
			}
		}
	}

	if m.inputMode {
		var cmd tea.Cmd
		m.pathInput, cmd = m.pathInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m MainMenuModel) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	b.WriteString(m.renderLogo())
	b.WriteString("\n")

	if m.inputMode {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGray)).
			Render(fmt.Sprintf("  %s path:", menuItems[m.choice].Name)))
		b.WriteString("\n  > ")
		b.WriteString(m.pathInput.View())
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGray)).
			Render("  enter: confirm   esc: back"))
	} else {
		for i, item := range menuItems {
			cursor := "  "
			if m.choice == i {
				cursor = lipgloss.NewStyle().
					Foreground(lipgloss.Color(ColorCyan)).
					Bold(true).
					Render(" > ")
			}

			name := lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorGray)).
				Width(16).
				Render(item.Name)

			desc := lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorDarkGray)).
				Render(item.Description)

			if m.choice == i {
				name = lipgloss.NewStyle().
					Foreground(lipgloss.Color(ColorWhite)).
					Bold(true).
					Width(16).
					Render(item.Name)
				desc = lipgloss.NewStyle().
					Foreground(lipgloss.Color(ColorGray)).
					Render(item.Description)
			}

			b.WriteString(fmt.Sprintf("  %s%s  %s\n", cursor, name, desc))
		}

		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorDarkGray)).
			Render("  up/down: navigate   enter: select   q: quit"))
	}

	b.WriteString("\n")
	return b.String()
}

func (m MainMenuModel) renderLogo() string {
	logo := `
  ______    ______   __    __      __  _______    ______    ______
 /      \  /      \ |  \  |  \    /  \|       \  /      \  /      \
|  $$$$$$\|  $$$$$$\| $$   \$$\  /  $$| $$$$$$$\|  $$$$$$\|  $$$$$$\
| $$   \$$| $$__| $$| $$    \$$\/  $$ | $$__/ $$| $$___\$$| $$  | $$
| $$      | $$    $$| $$     \$$  $$  | $$    $$ \$$    \ | $$  | $$
| $$   __ | $$$$$$$$| $$      \$$$$   | $$$$$$$  _\$$$$$$\| $$  | $$
| $$__/  \| $$  | $$| $$_____ | $$    | $$      |  \__| $$| $$__/ $$
 \$$    $$| $$  | $$| $$     \| $$    | $$       \$$    $$ \$$    $$
  \$$$$$$  \$$   \$$ \$$$$$$$$ \$$     \$$        \$$$$$$   \$$$$$$
      v0.1.0 — Defend before you open.`

	gradient := LogoStyle

	lines := strings.Split(logo, "\n")
	var styled []string
	for _, line := range lines {
		styled = append(styled, gradient.Render(line))
	}
	return strings.Join(styled, "\n")
}

func (m MainMenuModel) Submitted() bool {
	return m.submitted
}

func (m MainMenuModel) GetPath() string {
	return m.path
}

func (m MainMenuModel) GetAction() string {
	return m.action
}

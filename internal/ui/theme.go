package ui

import "github.com/charmbracelet/lipgloss"

const (
	ColorTeal     = "#00B4D8"
	ColorDeepBlue = "#023E8A"
	ColorCyan     = "#48CAE4"
	ColorCoral    = "#FF6B6B"
	ColorAmber    = "#FFB703"
	ColorGreen    = "#06D6A0"
	ColorGray     = "#6C757D"
	ColorDarkGray = "#343A40"
	ColorWhite    = "#F8F9FA"
	ColorBgDark   = "#0D1117"
	ColorBgCard   = "#161B22"
	ColorBorder   = "#30363D"
)

var (
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(ColorTeal)).
			MarginBottom(1)

	TaglineStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGray)).
			Italic(true).
			MarginBottom(1)

	VersionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorDeepBlue)).
			Bold(true)

	SpinnerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorCyan))

	StatusRunning = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorAmber)).
			Bold(true)

	StatusDone = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGreen)).
			Bold(true)

	StatusError = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorCoral)).
			Bold(true)

	StatusQueued = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGray))

	VerdictClean = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGreen)).
			Bold(true).
			Padding(0, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(ColorGreen))

	VerdictSuspicious = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorAmber)).
				Bold(true).
				Padding(0, 2).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color(ColorAmber))

	VerdictMalicious = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorCoral)).
				Bold(true).
				Padding(0, 2).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color(ColorCoral))

	FindingStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorWhite)).
			PaddingLeft(2)

	FindingRuleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorAmber)).
				Bold(true)

	FindingDescStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorGray))

	ProgressBarFill = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorTeal))

	ProgressBarEmpty = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorDarkGray))

	EngineNameStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorCyan)).
			Width(24)

	ActionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorTeal)).
			Bold(true).
			PaddingLeft(2)

	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(ColorBorder)).
			Padding(1, 2).
			MarginTop(1)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGreen)).
			Bold(true)

	WarnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorAmber)).
			Bold(true)

	FailStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorCoral)).
			Bold(true)

	SubtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorGray))

	LogoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorTeal)).
			Bold(true)
)

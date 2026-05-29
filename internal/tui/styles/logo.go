package styles

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// logoLines contains the ASCII art logo (small figlet font).
var logoLines = []string{
	" ___  ___ _  _ _____ _    ___ __  __   _   _  _ ",
	"/ __|| __|| \\| |_   _| |  | __|  \\/  | /_\\ | \\| |",
	"| (_ || _| | .` | | | | |__| _|| |\\/| |/ _ \\| .` |",
	" \\___||___||_|\\_| |_| |____|___||_|  |_/_/ \\_\\_|\\_|",
	"",
	"             ___    ___ ",
	"            / _ \\  |_ _|",
	"           /__/ \\__\\___|",
}

// gradientColors defines the top-to-bottom gradient for the logo.
var gradientColors = []lipgloss.Color{
	ColorMauve,    // band 1
	ColorLavender, // band 2
	ColorBlue,     // band 3
	ColorTeal,     // band 4
	ColorGreen,    // band 5
}

// RenderLogo returns the ASCII logo with a gradient foreground and a dark
// surface background, padded to a uniform block width.
func RenderLogo() string {
	total := len(logoLines)
	if total == 0 {
		return ""
	}

	const hPad = 2
	maxLen := 0
	for _, line := range logoLines {
		if len(line) > maxLen {
			maxLen = len(line)
		}
	}
	blockWidth := maxLen + hPad*2

	bands := len(gradientColors)
	var b strings.Builder

	for i, line := range logoLines {
		bandIdx := (i * bands) / total
		if bandIdx >= bands {
			bandIdx = bands - 1
		}
		padded := strings.Repeat(" ", hPad) + line +
			strings.Repeat(" ", blockWidth-hPad-len(line))
		style := lipgloss.NewStyle().
			Foreground(gradientColors[bandIdx]).
			Background(ColorSurface)
		b.WriteString(style.Render(padded))
		if i < total-1 {
			b.WriteByte('\n')
		}
	}

	return b.String()
}

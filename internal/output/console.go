// Package output renders results: live coloured console output and
// JSON / CSV / TXT report export.
package output

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/fatih/color"

	"github.com/sudosoc/rectool/internal/models"
)

var (
	cGreen  = color.New(color.FgGreen, color.Bold)
	cRed    = color.New(color.FgRed)
	cYellow = color.New(color.FgYellow)
	cCyan   = color.New(color.FgCyan, color.Bold)
	cDim    = color.New(color.Faint)
	cBold   = color.New(color.Bold)
)

// Console prints findings and progress. Safe for concurrent use.
type Console struct {
	mu       sync.Mutex
	out, err io.Writer
	progress atomic.Bool // a progress line is currently on screen
}

// NewConsole writes results to stdout and progress/diagnostics to stderr.
func NewConsole(noColor bool) *Console {
	if noColor {
		color.NoColor = true
	}
	return &Console{out: os.Stdout, err: os.Stderr}
}

func (c *Console) clearProgress() {
	if c.progress.Swap(false) {
		fmt.Fprint(c.err, "\r\033[K")
	}
}

// Banner prints the program header.
func (c *Console) Banner(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cCyan.Fprintf(c.err, "\n  rectool v%s", version)
	cDim.Fprintln(c.err, "  — API-less OSINT reconnaissance")
	cDim.Fprintln(c.err, "  Use only on subjects you are lawfully permitted to investigate.")
	fmt.Fprintln(c.err)
}

// Info prints a status line to stderr.
func (c *Console) Info(format string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgress()
	cCyan.Fprint(c.err, "[*] ")
	fmt.Fprintf(c.err, format+"\n", a...)
}

// Warn prints a warning line to stderr.
func (c *Console) Warn(format string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgress()
	cYellow.Fprint(c.err, "[!] ")
	fmt.Fprintf(c.err, format+"\n", a...)
}

// Error prints an error line to stderr.
func (c *Console) Error(format string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgress()
	cRed.Fprint(c.err, "[x] ")
	fmt.Fprintf(c.err, format+"\n", a...)
}

// Finding prints one positive result immediately: the headline plus a few
// of its most informative details.
func (c *Console) Finding(f models.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgress()
	if f.Status == models.StatusFound {
		cGreen.Fprint(c.out, "[+] ")
	} else {
		cYellow.Fprint(c.out, "[?] ")
	}
	cDim.Fprintf(c.out, "%-9s ", f.Module)
	cBold.Fprint(c.out, f.Source)
	if f.URL != "" {
		fmt.Fprintf(c.out, "  %s", f.URL)
	}
	cDim.Fprintf(c.out, "  (%.0f%%)", f.Confidence*100)
	if f.Via != "" {
		cDim.Fprintf(c.out, "  via %s", f.Via)
	}
	fmt.Fprintln(c.out)
	for _, l := range detailLines(f.Details, 4) {
		cDim.Fprintf(c.out, "              %s\n", l)
	}
}

// Progress draws a single self-overwriting progress line (throttled).
func (c *Console) Progress(module string, done, total int) {
	if total <= 0 || (done%20 != 0 && done != total) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if done == total {
		c.clearProgress()
		return
	}
	c.progress.Store(true)
	cDim.Fprintf(c.err, "\r\033[K    %s: %d/%d (%d%%)", module, done, total, done*100/total)
}

// Summary prints the end-of-run table.
func (c *Console) Summary(r *models.Report) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearProgress()
	fmt.Fprintln(c.out)
	cCyan.Fprintln(c.out, "── Summary ──────────────────────────────")
	for _, m := range r.Modules {
		name := m.Name
		if m.Via != "" {
			name += " <- " + m.Via
		}
		fmt.Fprintf(c.out, "  %-10s checked=%-5d found=", name, m.Checked)
		cGreen.Fprintf(c.out, "%-4d", m.Found)
		fmt.Fprintf(c.out, " errors=%-4d %5.1fs", m.Errors, float64(m.DurationMS)/1000)
		if m.Error != "" {
			cRed.Fprintf(c.out, "  ERROR: %s", m.Error)
		}
		fmt.Fprintln(c.out)
	}
	for _, s := range r.Skipped {
		cDim.Fprintf(c.out, "  skipped    %s\n", s)
	}
	if r.Interrupted {
		cYellow.Fprintln(c.out, "  run interrupted — results are partial")
	}
}

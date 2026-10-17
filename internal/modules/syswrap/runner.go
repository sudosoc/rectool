package syswrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// limitedBuf keeps at most max bytes and silently discards the rest, so a
// chatty tool cannot exhaust memory.
type limitedBuf struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if rem := l.max - l.buf.Len(); rem > 0 {
		if len(p) > rem {
			l.buf.Write(p[:rem])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// runCmd executes bin directly (never through a shell) with a hard timeout
// and an output cap. stdout is returned even when the command fails, because
// tools such as whois and dig exit non-zero yet still print useful data.
func runCmd(ctx context.Context, bin string, args []string, timeout time.Duration, maxOut int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.WaitDelay = 2 * time.Second
	stdout := &limitedBuf{max: maxOut}
	stderr := &limitedBuf{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	out := ansiRe.ReplaceAllString(stdout.buf.String(), "")
	if err == nil {
		return out, nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	if msg := strings.TrimSpace(stderr.buf.String()); msg != "" {
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return out, fmt.Errorf("%w: %s", err, msg)
	}
	return out, err
}

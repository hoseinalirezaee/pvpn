package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runner runs external commands.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// CmdError is a failed command.
type CmdError struct {
	Cmd    string
	Code   int
	Stderr string
}

func (e *CmdError) Error() string {
	s := strings.TrimSpace(e.Stderr)
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return fmt.Sprintf("%s: exit %d: %s", e.Cmd, e.Code, s)
}

// ExecRunner runs real commands with a clean locale.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.WaitDelay = 5 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return out.Bytes(), fmt.Errorf("%s: %w", name, ctx.Err())
		}
		var ee *exec.ExitError
		code := -1
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return out.Bytes(), &CmdError{Cmd: strings.Join(append([]string{name}, args...), " "), Code: code, Stderr: errb.String() + err.Error()}
	}
	return out.Bytes(), nil
}

// exitCode returns the exit code of a failed command, or 0 when err is nil, or -1.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ce *CmdError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return -1
}

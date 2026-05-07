//go:build darwin

// Package macauth holds the cached sudo password for the current process and
// runs networksetup commands under sudo on macOS. The cache lives only in
// memory — it never touches disk and is dropped when the process exits.
package macauth

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"ProxySwitch/internal/errs"
)

var (
	mu       sync.Mutex
	cachedPw string
	hasPw    bool
)

// HasPassword reports whether a password is currently cached.
func HasPassword() bool {
	mu.Lock()
	defer mu.Unlock()
	return hasPw
}

// Clear forgets the cached password (e.g. after detecting it became invalid).
func Clear() {
	mu.Lock()
	defer mu.Unlock()
	cachedPw = ""
	hasPw = false
}

// SetAndValidate validates the given password by running a no-op sudo command
// with -k (force re-prompt, bypassing the system 5-minute cache). On success
// the password is cached in memory.
func SetAndValidate(pw string) error {
	if pw == "" {
		return errs.ErrBadPassword
	}
	cmd := exec.Command("sudo", "-S", "-p", "", "-k", "true")
	cmd.Stdin = strings.NewReader(pw + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if isBadPwd(string(out)) {
			return errs.ErrBadPassword
		}
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	mu.Lock()
	cachedPw = pw
	hasPw = true
	mu.Unlock()
	return nil
}

// RunSudo joins the commands with " && " and runs them under sudo with the
// cached password. Returns ErrNeedPassword if no password has been cached yet.
// If the password turns out to be invalid mid-session, the cache is cleared
// and ErrBadPassword is returned.
func RunSudo(cmds []string) error {
	mu.Lock()
	pw := cachedPw
	has := hasPw
	mu.Unlock()
	if !has {
		return errs.ErrNeedPassword
	}
	script := strings.Join(cmds, " && ")
	cmd := exec.Command("sudo", "-S", "-p", "", "sh", "-c", script)
	cmd.Stdin = strings.NewReader(pw + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if isBadPwd(string(out)) {
			Clear()
			return errs.ErrBadPassword
		}
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func isBadPwd(out string) bool {
	low := strings.ToLower(out)
	return strings.Contains(low, "incorrect password") ||
		strings.Contains(low, "sorry, try again") ||
		strings.Contains(low, "1 incorrect password attempt")
}

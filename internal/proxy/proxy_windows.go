//go:build windows

package proxy

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"ProxySwitch/internal/errs"
	"ProxySwitch/internal/network"
)

const createNoWindow = 0x08000000

func runNetsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		low := strings.ToLower(text)
		if strings.Contains(low, "requires elevation") || strings.Contains(low, "access is denied") {
			return errs.ErrNeedElevation
		}
		if text == "" {
			text = err.Error()
		}
		return fmt.Errorf("%s", text)
	}
	return nil
}

func enable(iface *network.Interface, proxyIP string) error {
	nameArg := "name=" + iface.Name

	if err := runNetsh("interface", "ip", "set", "address",
		nameArg, "static", iface.IP, iface.Mask, proxyIP); err != nil {
		return err
	}

	if err := runNetsh("interface", "ip", "set", "dns",
		nameArg, "static", proxyIP); err != nil {
		// Strict-mode rollback: undo address change so we don't leave the NIC
		// half-proxied (gateway set but DNS not).
		_ = runNetsh("interface", "ip", "set", "address", nameArg, "dhcp")
		_ = runNetsh("interface", "ip", "set", "dns", nameArg, "dhcp")
		return fmt.Errorf("DNS 设置失败,已回滚: %w", err)
	}
	return nil
}

func disable(iface *network.Interface) error {
	nameArg := "name=" + iface.Name

	if err := runNetsh("interface", "ip", "set", "address", nameArg, "dhcp"); err != nil {
		return err
	}

	if err := runNetsh("interface", "ip", "set", "dns", nameArg, "dhcp"); err != nil {
		// Address is already DHCP; we just couldn't flip DNS back. Surface it
		// instead of silently leaving the NIC half-restored.
		return fmt.Errorf("DNS 恢复失败: %w", err)
	}
	return nil
}

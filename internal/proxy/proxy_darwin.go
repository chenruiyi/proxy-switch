//go:build darwin

package proxy

import (
	"fmt"
	"strings"

	"ProxySwitch/internal/macauth"
	"ProxySwitch/internal/network"
)

// shellQuote wraps s in single quotes for /bin/sh, escaping any embedded
// single quotes. Service names with spaces (e.g. "Wi-Fi") need this when we
// hand the joined script to `sh -c` under sudo.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func enable(iface *network.Interface, proxyIP string) error {
	svc := shellQuote(iface.Name)
	cmds := []string{
		fmt.Sprintf("networksetup -setmanual %s %s %s %s", svc, iface.IP, iface.Mask, proxyIP),
		fmt.Sprintf("networksetup -setdnsservers %s %s", svc, proxyIP),
	}
	if err := macauth.RunSudo(cmds); err != nil {
		// Best-effort rollback so the NIC isn't left half-proxied.
		_ = macauth.RunSudo([]string{
			fmt.Sprintf("networksetup -setdhcp %s", svc),
			fmt.Sprintf("networksetup -setdnsservers %s Empty", svc),
		})
		return err
	}
	return nil
}

func disable(iface *network.Interface) error {
	svc := shellQuote(iface.Name)
	cmds := []string{
		fmt.Sprintf("networksetup -setdhcp %s", svc),
		fmt.Sprintf("networksetup -setdnsservers %s Empty", svc),
	}
	return macauth.RunSudo(cmds)
}

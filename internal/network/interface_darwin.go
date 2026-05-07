//go:build darwin

package network

import (
	"fmt"
	"os/exec"
	"strings"

	"ProxySwitch/internal/errs"
)

func GetActive() (*Interface, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("查询网络服务失败: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		// First line is a notice header; skip it.
		lines = lines[1:]
	}
	for _, raw := range lines {
		svc := strings.TrimSpace(raw)
		if svc == "" || strings.HasPrefix(svc, "*") {
			continue
		}
		info, err := exec.Command("networksetup", "-getinfo", svc).Output()
		if err != nil {
			continue
		}
		iface := parseInfo(svc, string(info))
		if iface == nil {
			continue
		}
		if dnsOut, err := exec.Command("networksetup", "-getdnsservers", svc).Output(); err == nil {
			iface.DNS = parseDNS(string(dnsOut))
		}
		return iface, nil
	}
	return nil, errs.ErrNoActiveNIC
}

func parseInfo(svc, info string) *Interface {
	iface := &Interface{Name: svc}
	for _, line := range strings.Split(info, "\n") {
		switch {
		case strings.HasPrefix(line, "IP address: "):
			iface.IP = strings.TrimSpace(strings.TrimPrefix(line, "IP address:"))
		case strings.HasPrefix(line, "Subnet mask: "):
			iface.Mask = strings.TrimSpace(strings.TrimPrefix(line, "Subnet mask:"))
		case strings.HasPrefix(line, "Router: "):
			iface.Gateway = strings.TrimSpace(strings.TrimPrefix(line, "Router:"))
		}
	}
	if iface.IP == "" || iface.IP == "none" {
		return nil
	}
	return iface
}

func parseDNS(out string) []string {
	var dns []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "There aren't any DNS Servers") {
			continue
		}
		if strings.Contains(line, ".") {
			dns = append(dns, line)
		}
	}
	return dns
}

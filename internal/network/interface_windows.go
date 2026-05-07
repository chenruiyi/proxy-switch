//go:build windows

package network

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"ProxySwitch/internal/errs"
)

const createNoWindow = 0x08000000

func runPwsh(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return "", fmt.Errorf("%s", text)
	}
	return text, nil
}

func GetActive() (*Interface, error) {
	name, err := runPwsh(`Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name`)
	if err != nil {
		return nil, fmt.Errorf("查询网卡失败: %w", err)
	}
	if name == "" {
		return nil, errs.ErrNoActiveNIC
	}

	iface := &Interface{Name: name}

	ipScript := fmt.Sprintf(`Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -ne 'WellKnown'} | Select-Object IPAddress,PrefixLength | ConvertTo-Json -Compress`, name)
	ipOut, err := runPwsh(ipScript)
	if err != nil || ipOut == "" {
		return nil, errs.ErrCannotGetIP
	}

	type ipEntry struct {
		IPAddress    string `json:"IPAddress"`
		PrefixLength int    `json:"PrefixLength"`
	}
	var entries []ipEntry
	if strings.HasPrefix(ipOut, "[") {
		_ = json.Unmarshal([]byte(ipOut), &entries)
	} else {
		var single ipEntry
		if err := json.Unmarshal([]byte(ipOut), &single); err == nil {
			entries = []ipEntry{single}
		}
	}
	if len(entries) == 0 || entries[0].IPAddress == "" {
		return nil, errs.ErrCannotGetIP
	}
	iface.IP = entries[0].IPAddress
	iface.Mask = prefixToMask(entries[0].PrefixLength)

	gwScript := fmt.Sprintf(`(Get-NetIPConfiguration -InterfaceAlias '%s').IPv4DefaultGateway.NextHop`, name)
	if gw, err := runPwsh(gwScript); err == nil {
		iface.Gateway = gw
	}

	dnsScript := fmt.Sprintf(`(Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily IPv4).ServerAddresses -join ','`, name)
	if dnsOut, err := runPwsh(dnsScript); err == nil && dnsOut != "" {
		parts := strings.Split(dnsOut, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				iface.DNS = append(iface.DNS, p)
			}
		}
	}

	return iface, nil
}

func prefixToMask(prefix int) string {
	if prefix < 0 || prefix > 32 {
		return "255.255.255.0"
	}
	if prefix == 0 {
		return "0.0.0.0"
	}
	mask := uint32(0xffffffff) << (32 - prefix)
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xff, (mask>>16)&0xff, (mask>>8)&0xff, mask&0xff)
}

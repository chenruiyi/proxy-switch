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

// PowerShell cold-starts at ~1s on Windows. The original implementation made
// four separate calls (adapter / IP / gateway / DNS) so a single switch took
// ~5 seconds. Combining them into one script + one process drops the cost to
// ~1.5s — measurably the dominant remaining latency on Windows.
const getActiveScript = `
$ErrorActionPreference = 'Stop'
$adapter = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if ($null -eq $adapter) {
    Write-Output 'NO_ACTIVE_NIC'
    exit
}
$name = $adapter.Name
$ipObj = Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object -First 1
$gw = (Get-NetIPConfiguration -InterfaceAlias $name).IPv4DefaultGateway.NextHop
$dnsArr = @((Get-DnsClientServerAddress -InterfaceAlias $name -AddressFamily IPv4).ServerAddresses)
$result = [ordered]@{
    name = $name
    ip = if ($ipObj) { $ipObj.IPAddress } else { '' }
    prefix = if ($ipObj) { [int]$ipObj.PrefixLength } else { 0 }
    gateway = if ($gw) { $gw } else { '' }
    dns = $dnsArr
}
$result | ConvertTo-Json -Compress -Depth 4
`

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
	out, err := runPwsh(getActiveScript)
	if err != nil {
		return nil, fmt.Errorf("查询网络配置失败: %w", err)
	}
	if out == "NO_ACTIVE_NIC" {
		return nil, errs.ErrNoActiveNIC
	}

	var raw struct {
		Name    string          `json:"name"`
		IP      string          `json:"ip"`
		Prefix  int             `json:"prefix"`
		Gateway string          `json:"gateway"`
		DNS     json.RawMessage `json:"dns"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("解析网络配置失败: %s", out)
	}
	if raw.Name == "" || raw.IP == "" {
		return nil, errs.ErrCannotGetIP
	}

	iface := &Interface{
		Name:    raw.Name,
		IP:      raw.IP,
		Mask:    prefixToMask(raw.Prefix),
		Gateway: raw.Gateway,
		DNS:     parseDNS(raw.DNS),
	}
	return iface, nil
}

// parseDNS handles ConvertTo-Json's quirk: a single-element array may unbox
// to a string. Try array first, fall back to single string.
func parseDNS(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, s := range arr {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil && single != "" {
		return []string{single}
	}
	return nil
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

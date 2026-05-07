package proxy

import (
	"ProxySwitch/internal/network"
)

// Switch enables proxy on the active network interface by setting the gateway
// and DNS to proxyIP. The current IP/mask is preserved (taken from the live
// interface state). DNS-set failures trigger a rollback of the address change.
func Switch(proxyIP string) error {
	iface, err := network.GetActive()
	if err != nil {
		return err
	}
	return enable(iface, proxyIP)
}

// Restore reverts the active network interface back to DHCP for both address
// and DNS.
func Restore() error {
	iface, err := network.GetActive()
	if err != nil {
		return err
	}
	return disable(iface)
}

// DetectResidual returns true when the active interface is currently routing
// through proxyIP — either as gateway or DNS. Used at startup to recover from
// a previous run that didn't shut down cleanly.
func DetectResidual(proxyIP string) bool {
	iface, err := network.GetActive()
	if err != nil || iface == nil {
		return false
	}
	if iface.Gateway == proxyIP {
		return true
	}
	for _, d := range iface.DNS {
		if d == proxyIP {
			return true
		}
	}
	return false
}

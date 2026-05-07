package network

// Interface describes an active network interface in a platform-neutral way.
//   - On Windows, Name is the NIC alias (e.g. "Wi-Fi", "Ethernet").
//   - On macOS, Name is the network service name (e.g. "Wi-Fi", "USB 10/100/1000 LAN").
type Interface struct {
	Name    string
	IP      string
	Mask    string
	Gateway string
	DNS     []string
}

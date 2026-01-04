package proxy

import (
	"fmt"
	"net"
	"strings"
)

// IPManager handles IP validation and management for native IP rotation
type IPManager struct{}

// NewIPManager creates a new IP manager instance
func NewIPManager() *IPManager {
	return &IPManager{}
}

// ValidateLocalIP verifies that an IP address exists on local network interfaces
func (m *IPManager) ValidateLocalIP(ip string) error {
	// Parse and validate IP format
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}

	// Get all local network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to enumerate network interfaces: %w", err)
	}

	// Check if IP exists on any interface
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue // Skip interfaces that can't be queried
		}

		for _, addr := range addrs {
			var ifaceIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifaceIP = v.IP
			case *net.IPAddr:
				ifaceIP = v.IP
			default:
				continue
			}

			// Compare IPs (handle both IPv4 and IPv6)
			if ifaceIP.Equal(parsedIP) {
				return nil // IP found on local interface
			}
		}
	}

	return fmt.Errorf("IP address %s is not available on any local network interface", ip)
}

// GetLocalIPs returns a list of all available local IP addresses
func (m *IPManager) GetLocalIPs() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate network interfaces: %w", err)
	}

	ips := make(map[string]bool) // Use map to avoid duplicates
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			// Skip loopback addresses
			if ip.IsLoopback() {
				continue
			}

			// Convert to string (IPv4 or IPv6)
			ipStr := ip.String()
			ips[ipStr] = true
		}
	}

	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}

	return result, nil
}

// BindToIP creates a dialer bound to a specific local IP address
func (m *IPManager) BindToIP(ip string) (*net.Dialer, error) {
	// Validate IP first
	if err := m.ValidateLocalIP(ip); err != nil {
		return nil, err
	}

	// Parse IP to create TCP address
	// Use port 0 to let the system assign an ephemeral port
	localAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TCP address for %s: %w", ip, err)
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
	}

	return dialer, nil
}

// ParseIPAddress extracts IP address from address string
// Supports formats: "IP" or "IP:port"
func (m *IPManager) ParseIPAddress(address string) (string, error) {
	// Check if address contains a port
	if strings.Contains(address, ":") {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return "", fmt.Errorf("invalid address format: %s", address)
		}
		// Validate IP format
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("invalid IP address in address: %s", address)
		}
		return host, nil
	}

	// No port, treat entire string as IP
	if net.ParseIP(address) == nil {
		return "", fmt.Errorf("invalid IP address: %s", address)
	}

	return address, nil
}

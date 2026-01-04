package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/alpkeskin/rota/core/internal/models"
	proxyDialer "golang.org/x/net/proxy"
	"h12.io/socks"
)

// CreateProxyTransport creates an HTTP transport configured for the given proxy
// This is shared between proxy handler and health checker
func CreateProxyTransport(p *models.Proxy) (*http.Transport, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,             // Skip certificate verification for proxy connections
			MinVersion:         tls.VersionTLS10, // Support older TLS versions for compatibility
			MaxVersion:         0,                // Allow all TLS versions
			// Don't specify CipherSuites to accept all available ciphers for maximum compatibility
			// This is acceptable since InsecureSkipVerify is already true
		},
		// Timeouts for proxy connections
		// NOTE: Do NOT set DialContext here - it will override Proxy settings!
		// Let http.Transport handle proxy dialing automatically
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,
	}

	// Handle egress_ip protocol first - it doesn't need URL parsing
	switch p.Protocol {
	case "egress_ip":
		// Egress IP rotation: bind to local IP address
		ipManager := NewIPManager()

		// Parse IP address from address field (may contain port, but we only need IP)
		ip, err := ipManager.ParseIPAddress(p.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP address: %w", err)
		}

		// Validate IP exists on local interface
		if err := ipManager.ValidateLocalIP(ip); err != nil {
			return nil, fmt.Errorf("IP validation failed: %w", err)
		}

		// Create dialer bound to local IP
		dialer, err := ipManager.BindToIP(ip)
		if err != nil {
			return nil, fmt.Errorf("failed to bind to IP %s: %w", ip, err)
		}

		// Set DialContext to use the bound dialer
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}
		// Do NOT set transport.Proxy - this is a direct connection
		return transport, nil
	case "http", "https":
		// Parse proxy URL for HTTP/HTTPS protocols
		var proxyURL string
		var authMasked string // For logging (hide credentials)

		if p.Username != nil && *p.Username != "" {
			// Username exists, include authentication
			if p.Password != nil && *p.Password != "" {
				// Both username and password
				proxyURL = fmt.Sprintf("%s://%s:%s@%s", p.Protocol, *p.Username, *p.Password, p.Address)
				authMasked = fmt.Sprintf("%s://[username]:[password]@%s", p.Protocol, p.Address)
			} else {
				// Only username (API key), password is empty
				proxyURL = fmt.Sprintf("%s://%s:@%s", p.Protocol, *p.Username, p.Address)
				authMasked = fmt.Sprintf("%s://[api_key]:@%s", p.Protocol, p.Address)
			}
		} else {
			// No authentication
			proxyURL = fmt.Sprintf("%s://%s", p.Protocol, p.Address)
			authMasked = proxyURL
		}

		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %s: %w", authMasked, err)
		}
		// Set proxy URL - http.Transport will handle authentication headers automatically
		transport.Proxy = http.ProxyURL(parsedURL)
	case "socks4", "socks4a":
		// Parse proxy URL for SOCKS4 protocols
		var proxyURL string
		if p.Username != nil && *p.Username != "" {
			if p.Password != nil && *p.Password != "" {
				proxyURL = fmt.Sprintf("%s://%s:%s@%s", p.Protocol, *p.Username, *p.Password, p.Address)
			} else {
				proxyURL = fmt.Sprintf("%s://%s:@%s", p.Protocol, *p.Username, p.Address)
			}
		} else {
			proxyURL = fmt.Sprintf("%s://%s", p.Protocol, p.Address)
		}
		// Create SOCKS4/SOCKS4A dialer using h12.io/socks
		// The Dial function accepts URI format: socks4://[user@]host:port
		transport.Dial = socks.Dial(proxyURL)
	case "socks5":
		// Create SOCKS5 dialer
		var auth *proxyDialer.Auth
		if p.Username != nil && *p.Username != "" {
			// Username exists, create auth
			password := ""
			if p.Password != nil {
				password = *p.Password
			}
			auth = &proxyDialer.Auth{
				User:     *p.Username,
				Password: password,
			}
		}

		dialer, err := proxyDialer.SOCKS5("tcp", p.Address, auth, proxyDialer.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		transport.Dial = dialer.Dial
	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", p.Protocol)
	}

	return transport, nil
}

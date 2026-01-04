package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/alpkeskin/rota/core/internal/models"
	"github.com/alpkeskin/rota/core/internal/repository"
)

// ProxySelector defines the interface for proxy selection strategies
type ProxySelector interface {
	Select(ctx context.Context) (*models.Proxy, error)
	Refresh(ctx context.Context) error
}

// BaseSelector contains common fields for all selectors
type BaseSelector struct {
	repo     *repository.ProxyRepository
	proxies  []*models.Proxy
	settings *models.RotationSettings
	mu       sync.RWMutex
}

// RandomSelector selects a random proxy
type RandomSelector struct {
	*BaseSelector
}

// NewRandomSelector creates a new random selector
func NewRandomSelector(repo *repository.ProxyRepository, settings *models.RotationSettings) *RandomSelector {
	return &RandomSelector{
		BaseSelector: &BaseSelector{
			repo:     repo,
			proxies:  make([]*models.Proxy, 0),
			settings: settings,
		},
	}
}

// Select returns a random proxy from the available pool
func (s *RandomSelector) Select(ctx context.Context) (*models.Proxy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	// Thread-safe random number generation
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s.proxies))))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random number: %w", err)
	}

	fmt.Printf("[PROXY POOL] Selected proxy: %s\n", s.proxies[n.Int64()].Address)

	return s.proxies[n.Int64()], nil
}

// Refresh reloads the proxy list from database
func (s *RandomSelector) Refresh(ctx context.Context) error {
	proxies, err := s.loadActiveProxiesWithSettings(ctx, s.settings)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.proxies = proxies
	s.mu.Unlock()

	return nil
}

// RoundRobinSelector selects proxies in sequential order
type RoundRobinSelector struct {
	*BaseSelector
	index int
}

// NewRoundRobinSelector creates a new round-robin selector
func NewRoundRobinSelector(repo *repository.ProxyRepository, settings *models.RotationSettings) *RoundRobinSelector {
	return &RoundRobinSelector{
		BaseSelector: &BaseSelector{
			repo:     repo,
			proxies:  make([]*models.Proxy, 0),
			settings: settings,
		},
		index: 0,
	}
}

// Select returns the next proxy in round-robin fashion
func (s *RoundRobinSelector) Select(ctx context.Context) (*models.Proxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	proxy := s.proxies[s.index]
	s.index = (s.index + 1) % len(s.proxies)

	return proxy, nil
}

// Refresh reloads the proxy list from database
func (s *RoundRobinSelector) Refresh(ctx context.Context) error {
	proxies, err := s.loadActiveProxiesWithSettings(ctx, s.settings)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.proxies = proxies
	// Reset index if it's out of bounds
	if s.index >= len(s.proxies) {
		s.index = 0
	}
	s.mu.Unlock()

	return nil
}

// LeastConnectionsSelector selects the proxy with the lowest usage count
type LeastConnectionsSelector struct {
	*BaseSelector
}

// NewLeastConnectionsSelector creates a new least connections selector
func NewLeastConnectionsSelector(repo *repository.ProxyRepository, settings *models.RotationSettings) *LeastConnectionsSelector {
	return &LeastConnectionsSelector{
		BaseSelector: &BaseSelector{
			repo:     repo,
			proxies:  make([]*models.Proxy, 0),
			settings: settings,
		},
	}
}

// Select returns the proxy with the lowest request count
func (s *LeastConnectionsSelector) Select(ctx context.Context) (*models.Proxy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	// Find proxy with minimum requests
	minProxy := s.proxies[0]
	for _, proxy := range s.proxies[1:] {
		if proxy.Requests < minProxy.Requests {
			minProxy = proxy
		}
	}

	return minProxy, nil
}

// Refresh reloads the proxy list from database
func (s *LeastConnectionsSelector) Refresh(ctx context.Context) error {
	proxies, err := s.loadActiveProxiesWithSettings(ctx, s.settings)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.proxies = proxies
	s.mu.Unlock()

	return nil
}

// TimeBasedSelector selects proxy based on time intervals
type TimeBasedSelector struct {
	*BaseSelector
	interval time.Duration
}

// NewTimeBasedSelector creates a new time-based selector
func NewTimeBasedSelector(repo *repository.ProxyRepository, settings *models.RotationSettings, intervalSeconds int) *TimeBasedSelector {
	return &TimeBasedSelector{
		BaseSelector: &BaseSelector{
			repo:     repo,
			proxies:  make([]*models.Proxy, 0),
			settings: settings,
		},
		interval: time.Duration(intervalSeconds) * time.Second,
	}
}

// Select returns a proxy based on current time interval
func (s *TimeBasedSelector) Select(ctx context.Context) (*models.Proxy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	// Calculate index based on time intervals
	now := time.Now().Unix()
	intervalCount := now / int64(s.interval.Seconds())
	index := int(intervalCount) % len(s.proxies)

	return s.proxies[index], nil
}

// Refresh reloads the proxy list from database
func (s *TimeBasedSelector) Refresh(ctx context.Context) error {
	proxies, err := s.loadActiveProxiesWithSettings(ctx, s.settings)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.proxies = proxies
	s.mu.Unlock()

	return nil
}

// Helper function to load active proxies from database
func (b *BaseSelector) loadActiveProxies(ctx context.Context) ([]*models.Proxy, error) {
	return b.loadActiveProxiesWithSettings(ctx, nil)
}

// Helper function to load active proxies from database with settings filters
func (b *BaseSelector) loadActiveProxiesWithSettings(ctx context.Context, settings *models.RotationSettings) ([]*models.Proxy, error) {
	// Get all active and idle proxies (not failed)
	query := `
		SELECT
			id, address, protocol, username, password, status,
			requests, successful_requests, failed_requests,
			avg_response_time, last_check, last_error, created_at, updated_at
		FROM proxies
		WHERE status IN ('active', 'idle')
		ORDER BY address
	`

	rows, err := b.repo.GetDB().Pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to load proxies: %w", err)
	}
	defer rows.Close()

	allProxies := make([]*models.Proxy, 0)
	proxies := make([]*models.Proxy, 0)

	// First, collect all proxies from database
	for rows.Next() {
		var p models.Proxy
		err := rows.Scan(
			&p.ID, &p.Address, &p.Protocol, &p.Username, &p.Password, &p.Status,
			&p.Requests, &p.SuccessfulRequests, &p.FailedRequests,
			&p.AvgResponseTime, &p.LastCheck, &p.LastError, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proxy: %w", err)
		}
		allProxies = append(allProxies, &p)
	}

	// Log total proxies found
	if len(allProxies) == 0 {
		return nil, fmt.Errorf("no active or idle proxies found in database")
	}

	// Apply filters if settings provided
	if settings != nil {
		// Rotation mode filter - filter by mode (proxy vs ip)
		mode := settings.Mode
		if mode == "" {
			mode = "proxy" // Default to proxy mode for backward compatibility
		}

		// Log filtering info for debugging
		fmt.Printf("[PROXY FILTER] Mode: %s, Allowed Protocols: %v, Total proxies before filter: %d\n",
			mode, settings.AllowedProtocols, len(allProxies))

		// Filter each proxy
		for _, p := range allProxies {
			// Mode-based protocol filter
			if mode == "ip" || mode == "egress_ip" {
				// IP rotation mode: only allow "egress_ip" protocol
				if p.Protocol != "egress_ip" {
					continue // Skip non-egress_ip protocols in IP mode
				}
			} else if mode == "proxy" {
				// Proxy rotation mode: only allow traditional proxy protocols
				// Exclude "egress_ip" from proxy mode
				proxyProtocols := map[string]bool{
					"http":    true,
					"https":   true,
					"socks4":  true,
					"socks4a": true,
					"socks5":  true,
				}
				if !proxyProtocols[p.Protocol] {
					continue // Skip egress_ip and other non-proxy protocols in proxy mode
				}
			}

			// Protocol filter (additional filtering by allowed protocols)
			// Note: If mode is set, the mode filter above already ensures correct protocol type
			// This filter is for additional fine-grained control within the mode
			if len(settings.AllowedProtocols) > 0 {
				allowed := false
				for _, protocol := range settings.AllowedProtocols {
					if p.Protocol == protocol {
						allowed = true
						break
					}
				}
				if !allowed {
					continue
				}
			}

			// Max response time filter
			if settings.MaxResponseTime > 0 && p.AvgResponseTime > settings.MaxResponseTime {
				continue
			}

			// Min success rate filter
			if settings.MinSuccessRate > 0 && p.Requests > 0 {
				successRate := (float64(p.SuccessfulRequests) / float64(p.Requests)) * 100
				if successRate < settings.MinSuccessRate {
					continue
				}
			}

			proxies = append(proxies, p)
		}

		// Log filtering results
		fmt.Printf("[PROXY FILTER] After filtering: %d proxies available (from %d total)\n", len(proxies), len(allProxies))
	} else {
		// No settings, include all proxies
		proxies = allProxies
		fmt.Printf("[PROXY FILTER] No settings, including all %d proxies\n", len(proxies))
	}

	if len(proxies) == 0 {
		mode := "proxy"
		allowedProtocols := []string{}
		if settings != nil {
			mode = settings.Mode
			if mode == "" {
				mode = "proxy"
			}
			allowedProtocols = settings.AllowedProtocols
		}

		// Provide detailed error message
		totalCount := len(allProxies)
		var protocolCounts map[string]int
		var statusCounts map[string]int
		if totalCount > 0 {
			protocolCounts = make(map[string]int)
			statusCounts = make(map[string]int)
			for _, p := range allProxies {
				protocolCounts[p.Protocol]++
				statusCounts[p.Status]++
			}
		}

		errMsg := fmt.Sprintf("no proxies matching filters (mode: %s, allowed_protocols: %v)", mode, allowedProtocols)
		if totalCount > 0 {
			errMsg += fmt.Sprintf(". Found %d proxies in database - protocols: %v, statuses: %v", totalCount, protocolCounts, statusCounts)

			// Add helpful suggestion based on mode
			if mode == "ip" || mode == "egress_ip" {
				if protocolCounts["egress_ip"] == 0 {
					errMsg += ". No egress_ip proxies found. Add egress_ip proxies or change mode to 'proxy'"
				} else {
					errMsg += ". Egress IP proxies exist but may be filtered by allowed_protocols or other filters"
				}
			} else {
				proxyCount := protocolCounts["http"] + protocolCounts["https"] + protocolCounts["socks4"] + protocolCounts["socks4a"] + protocolCounts["socks5"]
				if proxyCount == 0 {
					errMsg += ". No HTTP/HTTPS/SOCKS proxies found. Add proxy servers or change mode to 'ip'"
				} else {
					errMsg += ". Proxy servers exist but may be filtered by allowed_protocols or other filters"
				}
			}
		} else {
			errMsg += ". No proxies found in database with status 'active' or 'idle'"
		}

		return nil, fmt.Errorf(errMsg)
	}

	return proxies, nil
}

// NewProxySelector creates a proxy selector based on settings
func NewProxySelector(repo *repository.ProxyRepository, settings *models.RotationSettings) (ProxySelector, error) {
	switch settings.Method {
	case "random":
		return NewRandomSelector(repo, settings), nil
	case "roundrobin", "round-robin":
		return NewRoundRobinSelector(repo, settings), nil
	case "least_conn", "least-conn", "least_connections":
		return NewLeastConnectionsSelector(repo, settings), nil
	case "time_based", "time-based":
		interval := settings.TimeBased.Interval
		if interval <= 0 {
			interval = 120 // Default 2 minutes
		}
		return NewTimeBasedSelector(repo, settings, interval), nil
	default:
		// Default to random
		return NewRandomSelector(repo, settings), nil
	}
}

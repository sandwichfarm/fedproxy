package silentproxy

import (
	"fmt"
	"net"

	"github.com/sandwichfarm/hedproxy/internal/logging"
	"golang.org/x/net/proxy"
)

// SilentDialer wraps a proxy.Dialer and suppresses error output when in SILENT mode
type SilentDialer struct {
	underlying proxy.Dialer
}

func (s *SilentDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := s.underlying.Dial(network, addr)
	// Return the error but don't log it
	return conn, err
}

// SOCKS5 creates a SOCKS5 dialer with error suppression when in SILENT mode
func SOCKS5(network, addr string, auth *proxy.Auth, forward proxy.Dialer) (proxy.Dialer, error) {
	// Use the underlying proxy.SOCKS5 to create the dialer
	dialer, err := proxy.SOCKS5(network, addr, auth, forward)
	if err != nil {
		// Only log error if not in SILENT mode
		if logging.GetCurrentLevel() != logging.SILENT {
			fmt.Printf("Error creating SOCKS5 proxy: %v\n", err)
		}
		return nil, err
	}
	
	// If in SILENT mode, wrap the dialer to suppress errors
	if logging.GetCurrentLevel() == logging.SILENT {
		return &SilentDialer{underlying: dialer}, nil
	}
	
	return dialer, nil
} 
package socks5

import (
	"log"
	
	"github.com/sandwichfarm/hedproxy/internal/logging"
)

// Custom io.Writer that forwards everything directly to our logging system
type socks5LogWriter struct{}

func (w *socks5LogWriter) Write(p []byte) (n int, err error) {
	// Simply direct everything to the DEBUG level in our main logger
	// The main logger already handles log levels correctly
	if logging.GetCurrentLevel() != logging.SILENT {
		logging.Debug("%s", string(p))
	}
	return len(p), nil
}

// CreateLogger creates a stub logger for the socks5 package
// that forwards everything to our main logging system
func CreateLogger() *log.Logger {
	// Return a logger that writes to our custom writer
	return log.New(&socks5LogWriter{}, "", 0)
} 
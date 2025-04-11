package socks5

import (
	"log"
	"strings"
	
	"github.com/sandwichfarm/hedproxy/internal/logging"
)

// logWriter is an io.Writer that directs output to our logging system
type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Trim trailing newlines that might prevent log messages from showing
	msg = strings.TrimRight(msg, "\r\n")
	
	// Skip empty messages
	if msg == "" {
		return len(p), nil
	}
	
	// Use appropriate log level based on message content
	msgLower := strings.ToLower(msg)
	if strings.Contains(msgLower, "[err]") || strings.Contains(msgLower, "error") || strings.Contains(msgLower, "failed") {
		logging.Error("SOCKS5: %s", msg)
	} else if strings.Contains(msgLower, "warn") {
		logging.Warning("SOCKS5: %s", msg)
	} else if strings.Contains(msgLower, "connect") || strings.Contains(msgLower, "dialing") || strings.Contains(msgLower, "new connection") {
		logging.Notice("SOCKS5: %s", msg)
	} else if strings.Contains(msgLower, "success") || strings.Contains(msgLower, "established") || strings.Contains(msgLower, "completed") {
		logging.Info("SOCKS5: %s", msg)
	} else {
		logging.Debug("SOCKS5: %s", msg)
	}
	
	return len(p), nil
}

// CreateLogger creates a standard *log.Logger that sends logs to our logging system
func CreateLogger() *log.Logger {
	return log.New(&logWriter{}, "", 0) // No prefix, no flags (we'll handle formatting)
} 
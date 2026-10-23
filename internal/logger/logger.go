// Package logger provides a structured slog-based JSON logger for monitorctl.
//
// Every log record emitted by monitorctl is JSON, on stdout by default, or
// appended to the file specified by --log-file. Non-JSON logging (fmt.Println
// etc.) is forbidden in library code; only main() may fail loudly on startup.
package logger

import (
	"fmt"
	"log/slog"
	"os"
)

// New returns a slog.Logger that writes JSON records to logFilePath.
//
// If logFilePath is empty, records are written to stdout and the returned
// closer is a no-op. Otherwise the file is opened in append mode with 0600
// permissions; the returned closer must be invoked (typically via defer) to
// release the underlying file descriptor.
//
// Example:
//
//	log, closeLog, err := logger.New("/var/log/monitorctl.json")
//	if err != nil { return err }
//	defer closeLog()
//	log.Info("monitorctl starting", "version", "v0.1.0")
func New(logFilePath string) (*slog.Logger, func(), error) {
	if logFilePath == "" {
		return slog.New(slog.NewJSONHandler(os.Stdout, nil)), func() {}, nil
	}

	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %q: %w", logFilePath, err)
	}
	return slog.New(slog.NewJSONHandler(f, nil)), func() { _ = f.Close() }, nil
}

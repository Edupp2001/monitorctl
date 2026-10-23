package logger

import (
	"io"
	"log/slog"
)

// CloseOrLog closes c and logs any error under the given name. It is intended
// for deferred cleanup where the close error is not actionable but should not
// be silently dropped.
//
// If c is nil, CloseOrLog returns immediately. If log is nil, slog.Default()
// is used. The what argument names the resource ("log file", "bpf link",
// "control socket") and appears as the "what" attribute of the error record.
//
// Example:
//
//	f, err := os.Open(path)
//	if err != nil {
//		return fmt.Errorf("open %s: %w", path, err)
//	}
//	defer logger.CloseOrLog(f, log, "input file")
func CloseOrLog(c io.Closer, log *slog.Logger, what string) {
	if c == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	if err := c.Close(); err != nil {
		log.Error("close failed", "what", what, "error", err.Error())
	}
}

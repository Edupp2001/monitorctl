package logger_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/monitorctl/internal/logger"
)

func TestNewStdout(t *testing.T) {
	log, closeLog, err := logger.New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	closeLog()
	if log == nil {
		t.Fatal("nil logger")
	}
}

func TestNewFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	log, closeLog, err := logger.New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	log.Info("hello", "k", "v")
	closeLog()

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, data)
	}
	if rec["msg"] != "hello" || rec["k"] != "v" {
		t.Fatalf("unexpected record: %v", rec)
	}
}

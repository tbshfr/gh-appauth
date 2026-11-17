package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeRejectsBadTokensPerMinute(t *testing.T) {
	db := filepath.Join(t.TempDir(), "b.db")
	for _, v := range []string{"0", "-5"} {
		if err := cmdServe([]string{"-db", db, "-tokens-per-minute", v}); err == nil || !strings.Contains(err.Error(), "-tokens-per-minute") {
			t.Errorf("-tokens-per-minute %s: %v", v, err)
		}
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Errorf("database created before the flags were checked: %v", err)
	}
}

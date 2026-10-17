//go:build linux

package network

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"syswarden-core/config"
)

func TestExplicitProducerFollowerRotatesAndRefusesUntrustedReplacement(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("audit.log", []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := root.Open("audit.log")
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	producer := stat.Uid
	path := filepath.Join(root.Name(), "audit.log")
	access := config.TrustedLogAccess{AuthorityUID: int64(producer) + 1, ProducerUID: &producer}
	if f, err := newSecureWAAPLogFollowerWithAccess(path, false, config.TrustedLogAccess{AuthorityUID: int64(producer) + 1}); err == nil {
		_ = f.Close()
		t.Fatal("missing producer grant accepted")
	}
	follower, err := newSecureWAAPLogFollowerWithAccess(path, false, access)
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()
	if got := nextWAAPTestLine(t, follower); got != "first" {
		t.Fatal(got)
	}
	if err := root.Remove("audit.log"); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("audit.log", []byte("rotated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := nextWAAPTestLine(t, follower); got != "rotated" {
		t.Fatal(got)
	}
	if err := root.Rename("audit.log", "audit.log.1"); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("audit.log", []byte("unsafe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("audit.log", 0666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if text, err := follower.Next(ctx); err == nil || text != "" || !strings.Contains(err.Error(), "write bits") {
		t.Fatalf("replacement accepted: %q %v", text, err)
	}
}

func TestFollowerRefusesParentDriftBeforeRotation(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("logs", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("logs/audit.log", nil, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root.Name(), "logs", "audit.log")
	follower, err := newSecureWAAPLogFollower(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()
	if err := root.Rename("logs", "old"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir("logs", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("logs/audit.log", []byte("replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if text, err := follower.Next(ctx); err == nil || text != "" || !strings.Contains(err.Error(), "parent was replaced") {
		t.Fatalf("parent drift accepted: %q %v", text, err)
	}
}

func TestWAAPProducerPolicyIsScopedAndMalformedPolicyDisablesCollection(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("waap.trusted_log_producers", "/srv/waf/audit.log=999")
	cfg := loadWAAPConfig()
	if cfg.producerPolicyError != nil || cfg.TrustedLogProducers["/srv/waf/audit.log"] != 999 {
		t.Fatal(cfg)
	}
	enrolled := false
	for _, path := range cfg.Logs {
		enrolled = enrolled || path == "/srv/waf/audit.log"
	}
	if !enrolled {
		t.Fatal("grant not enrolled")
	}
	if waapLogAccess("/srv/waf/other.log", cfg.TrustedLogProducers).ProducerUID != nil {
		t.Fatal("grant leaked to another path")
	}
	if waapLogAccess("/srv/waf/audit.log", cfg.TrustedLogProducers).ProducerUID == nil {
		t.Fatal("exact grant lost")
	}
	viper.Set("waap.trusted_log_producers", "/srv/waf/*.log=999")
	cfg = loadWAAPConfig()
	if cfg.producerPolicyError == nil {
		t.Fatal("malformed policy silently defaulted")
	}
	engine := &WAAPEngine{config: cfg}
	engine.StartContext(context.Background())
	engine.Wait()
}

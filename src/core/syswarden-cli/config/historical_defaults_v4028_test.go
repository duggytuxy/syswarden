package config

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestHistoricalDefaultModelsBindOfficialV4028Renderer(t *testing.T) {
	// These complete templates come from the v4.02.8 renderer at commit
	// 371d353e871fedb410b08f0618a1ae6aa2f7fedc. Both the original source
	// renderer and the original package independently produced these bytes.
	if got := fmt.Sprintf("%x", sha256.Sum256(historicalDefaultModelsV4028)); got != "89866aa17c221762a049d338f6544d542322eb1e68f6c2c39eb47522567988ff" {
		t.Fatal("historical default fixture changed", got)
	}
	models, err := DefaultModularFileVariants("/etc/syswarden/config")
	if err != nil || len(models) != 7 {
		t.Fatal("incomplete historical model inventory", err)
	}
	for path, variants := range models {
		if len(variants) < 2 || variants[0] == "" || variants[1] == "" {
			t.Fatal("missing complete template", path)
		}
	}
}

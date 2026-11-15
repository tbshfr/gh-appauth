package buildinfo

import "testing"

func TestResolveStamped(t *testing.T) {
	if got := Resolve("v1.2.3"); got != "v1.2.3" {
		t.Errorf("Resolve(v1.2.3) = %q", got)
	}
	if got := Resolve("dev"); got == "" {
		t.Error("Resolve(dev) is empty")
	}
}

func TestReleaseURL(t *testing.T) {
	for v, want := range map[string]string{
		"v1.2.3":                             "https://github.com/tbshfr/gh-appauth/releases/tag/v1.2.3",
		"dev":                                "https://github.com/tbshfr/gh-appauth/releases",
		"v1.2.3-dirty":                       "https://github.com/tbshfr/gh-appauth/releases",
		"v1.2.3-4-gabcdef0":                  "https://github.com/tbshfr/gh-appauth/releases",
		"v1.2.4-0.20260101120000-abcdef0123": "https://github.com/tbshfr/gh-appauth/releases",
		"v1.2.3+dirty":                       "https://github.com/tbshfr/gh-appauth/releases",
	} {
		if got := ReleaseURL(v); got != want {
			t.Errorf("ReleaseURL(%q) = %q, want %q", v, got, want)
		}
	}
}

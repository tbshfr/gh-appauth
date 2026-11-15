package repo

import "testing"

func TestParse(t *testing.T) {
	ok := map[string]string{
		"acme/web":                               "acme/web",
		"github.com/acme/web":                    "acme/web",
		"GitHub.com/acme/web":                    "acme/web",
		"https://github.com/acme/web":            "acme/web",
		"https://github.com/acme/web.git":        "acme/web",
		"https://github.com/acme/web/":           "acme/web",
		"https://x-access-token@github.com/a/b":  "a/b",
		"ssh://git@github.com/acme/web":          "acme/web",
		"ssh://git@github.com/acme/web.git":      "acme/web",
		"git@github.com:acme/web.git":            "acme/web",
		"git@github.com:acme/web":                "acme/web",
		"acme/my.repo_name-2":                    "acme/my.repo_name-2",
		"  acme/web\n":                           "acme/web",
		"https://github.com/Acme-Corp/API-Core":  "Acme-Corp/API-Core",
		"https://github.com:443/acme/web.git":    "acme/web",
		"ssh://git@github.com:22/acme/web.git":   "acme/web",
		"https://user:pass@github.com/acme/web":  "acme/web",
		"git://github.com/acme/web.git":          "acme/web",
		"http://github.com/acme/web":             "acme/web",
		"github.com/acme/web.git":                "acme/web",
		"acme/web.git":                           "acme/web",
		"a/b":                                    "a/b",
		"acme/.github":                           "acme/.github",
		"acme/web/":                              "acme/web",
		"/acme/web":                              "acme/web",
		"https://github.com/acme/web.git/":       "acme/web",
		"git@github.com:/acme/web.git":           "acme/web",
		"ssh://github.com/acme/web":              "acme/web",
		"https://GITHUB.COM/acme/web":            "acme/web",
		"git@GitHub.com:acme/web":                "acme/web",
		"https://github.com/acme/web?x=1":        "acme/web",
		"https://github.com/acme/web#frag":       "acme/web",
		"https://github.com/acme/web.git?x=1#xx": "acme/web",
	}
	for in, want := range ok {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "acme", "acme/web/extra", "gitlab.com/acme/web", "https://gitlab.com/acme/web",
		"git@gitlab.com:acme/web", "ftp://github.com/acme/web", "acme/../../app", "acme/..",
		"acme/.", "-acme/web", "acme/we b", "acme/web%2f", "https://github.com/acme",
		"https://github.com/acme/web/tree/main", "acme//web", "github.com/acme/web/x",
		"acme/" + string(make([]byte, 101)),
	}
	for _, in := range bad {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %q, want error", in, got)
		}
	}
}

func TestParseHost(t *testing.T) {
	got, err := ParseHost("https://ghe.example.com/acme/web.git", "ghe.example.com")
	if err != nil || got != "acme/web" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ParseHost("https://github.com/acme/web", "ghe.example.com"); err == nil {
		t.Fatal("expected host mismatch error")
	}
}

func TestValid(t *testing.T) {
	for _, s := range []string{"acme/web", "a/b", "acme/.github"} {
		if !Valid(s) {
			t.Errorf("Valid(%q) = false", s)
		}
	}
	for _, s := range []string{"acme/../../app", "acme/x/y", "acme/..", "../x", "acme/", "/web"} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}

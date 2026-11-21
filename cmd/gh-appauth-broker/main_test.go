package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain clears GH_APPAUTH_BROKER_* so variables from the developer's shell
// can't change how the tests configure the broker.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, envPrefix) {
			os.Unsetenv(k)
		}
	}
	os.Exit(m.Run())
}

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

func testFlagSet() (*flag.FlagSet, *string, *int, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs, fs.String("ui-listen", "", "admin UI `address`"), fs.Int("tokens-per-minute", 60, "rate"), fs.Bool("dry-run", false, "dry run")
}

func TestParseFlagsEnv(t *testing.T) {
	t.Setenv("GH_APPAUTH_BROKER_UI_LISTEN", "127.0.0.1:8444")
	t.Setenv("GH_APPAUTH_BROKER_TOKENS_PER_MINUTE", "240")
	t.Setenv("GH_APPAUTH_BROKER_DRY_RUN", "true")
	t.Setenv("GH_APPAUTH_BROKER_NOT_A_FLAG", "whatever")
	fs, ui, tpm, dry := testFlagSet()
	if err := parseFlags(fs, nil); err != nil {
		t.Fatal(err)
	}
	if *ui != "127.0.0.1:8444" || *tpm != 240 || !*dry {
		t.Errorf("got ui=%q tpm=%d dry=%v", *ui, *tpm, *dry)
	}
}

func TestParseFlagsCommandLineBeatsEnv(t *testing.T) {
	t.Setenv("GH_APPAUTH_BROKER_UI_LISTEN", "127.0.0.1:8444")
	t.Setenv("GH_APPAUTH_BROKER_TOKENS_PER_MINUTE", "240")
	t.Setenv("GH_APPAUTH_BROKER_DRY_RUN", "true")
	fs, ui, tpm, dry := testFlagSet()
	if err := parseFlags(fs, []string{"-ui-listen", "off", "-tokens-per-minute", "5", "-dry-run=false"}); err != nil {
		t.Fatal(err)
	}
	if *ui != "off" || *tpm != 5 || *dry {
		t.Errorf("got ui=%q tpm=%d dry=%v", *ui, *tpm, *dry)
	}
}

func TestParseFlagsEmptyEnvIgnored(t *testing.T) {
	t.Setenv("GH_APPAUTH_BROKER_UI_LISTEN", "")
	t.Setenv("GH_APPAUTH_BROKER_TOKENS_PER_MINUTE", "")
	t.Setenv("GH_APPAUTH_BROKER_DRY_RUN", "")
	fs, ui, tpm, dry := testFlagSet()
	if err := parseFlags(fs, nil); err != nil {
		t.Fatal(err)
	}
	if *ui != "" || *tpm != 60 || *dry {
		t.Errorf("got ui=%q tpm=%d dry=%v", *ui, *tpm, *dry)
	}
}

func TestParseFlagsBadEnv(t *testing.T) {
	for name, v := range map[string]string{
		"GH_APPAUTH_BROKER_TOKENS_PER_MINUTE": "abc",
		"GH_APPAUTH_BROKER_DRY_RUN":           "maybe",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, v)
			fs, _, _, _ := testFlagSet()
			err := parseFlags(fs, nil)
			if err == nil || !strings.HasPrefix(err.Error(), name+`: invalid value "`+v+`"`) {
				t.Errorf("got %v", err)
			}
		})
	}
	// A bad value is fine when the command line overrides it.
	t.Setenv("GH_APPAUTH_BROKER_TOKENS_PER_MINUTE", "abc")
	fs, _, tpm, _ := testFlagSet()
	if err := parseFlags(fs, []string{"-tokens-per-minute", "7"}); err != nil || *tpm != 7 {
		t.Errorf("got %d, %v", *tpm, err)
	}
}

func TestServeBadEnv(t *testing.T) {
	t.Setenv("GH_APPAUTH_BROKER_TOKENS_PER_MINUTE", "0")
	err := cmdServe([]string{"-db", filepath.Join(t.TempDir(), "b.db")})
	if err == nil || !strings.Contains(err.Error(), "-tokens-per-minute") {
		t.Errorf("got %v", err)
	}
}

// A value that doesn't parse exits 2, like a bad command-line flag. That
// happens inside cmdServe, so it runs in a child process.
func TestServeUnparsableEnvExits2(t *testing.T) {
	if os.Getenv("GAA_TEST_CHILD") == "1" {
		os.Setenv("GH_APPAUTH_BROKER_HISTORY_DAYS", "x") // TestMain cleared the inherited environment
		cmdServe([]string{"-db", filepath.Join(t.TempDir(), "b.db")})
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestServeUnparsableEnvExits2$")
	cmd.Env = append(os.Environ(), "GAA_TEST_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("got %v, want exit status 2; stderr:\n%s", err, stderr.String())
	}
	if want := `GH_APPAUTH_BROKER_HISTORY_DAYS: invalid value "x"`; !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
	}
}

func TestParseFlagsUsageNamesEnv(t *testing.T) {
	fs, _, _, _ := testFlagSet()
	var out bytes.Buffer
	fs.SetOutput(&out)
	if err := parseFlags(fs, []string{"-h"}); err != flag.ErrHelp {
		t.Fatalf("got %v", err)
	}
	for _, want := range []string{
		"-ui-listen address\n",
		"admin UI address (env GH_APPAUTH_BROKER_UI_LISTEN)",
		"(env GH_APPAUTH_BROKER_TOKENS_PER_MINUTE) (default 60)",
		"(env GH_APPAUTH_BROKER_DRY_RUN)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, out.String())
		}
	}
}

func TestDBFlagEnv(t *testing.T) {
	dir := t.TempDir()
	def, err := defaultDataDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		envDB, envDir string
		args          []string
		want          string
	}{
		{"default", "", "", nil, filepath.Join(def, "broker.db")},
		{"env db", "/e/env.db", "", nil, "/e/env.db"},
		{"env data dir", "", "/e/dir", nil, "/e/dir/broker.db"},
		{"env db beats env data dir", "/e/env.db", "/e/dir", nil, "/e/env.db"},
		{"flag db beats env", "/e/env.db", "/e/dir", []string{"-db", dir + "/f.db"}, dir + "/f.db"},
		{"flag data dir beats env db", "/e/env.db", "", []string{"-data-dir", dir}, dir + "/broker.db"},
		{"flag data dir beats env data dir", "", "/e/dir", []string{"-data-dir", dir}, dir + "/broker.db"},
		{"flag db beats flag data dir", "", "", []string{"-data-dir", "/x", "-db", dir + "/f.db"}, dir + "/f.db"},
		{"flag db beats env data dir", "", "/e/dir", []string{"-db", dir + "/f.db"}, dir + "/f.db"},
		{"explicit empty flag db blocks env db", "/e/env.db", "", []string{"-db", ""}, filepath.Join(def, "broker.db")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GH_APPAUTH_BROKER_DB", tc.envDB)
			t.Setenv("GH_APPAUTH_BROKER_DATA_DIR", tc.envDir)
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			db := dbFlag(fs)
			if err := parseFlags(fs, tc.args); err != nil {
				t.Fatal(err)
			}
			if got, err := db(); err != nil || got != tc.want {
				t.Errorf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// Command gh-appauth-broker holds GitHub App private keys and hands out
// short-lived, single-repo installation tokens to authenticated clients.
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const usage = `gh-appauth-broker: GitHub App token broker

Usage:
  gh-appauth-broker serve [flags]   run the broker (see serve -h)
  gh-appauth-broker check           validate the stored configuration and keys
  gh-appauth-broker set-password    set the admin UI password (read from stdin)
  gh-appauth-broker fingerprint     print the self-signed certificate fingerprint

Every command takes -data-dir DIR or -db FILE. The database defaults to
data/broker.db next to the gh-appauth-broker binary.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = cmdServe(args)
	case "check":
		err = cmdCheck(args)
	case "set-password":
		err = cmdSetPassword(args)
	case "fingerprint":
		err = cmdFingerprint(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: %v\n", err)
		os.Exit(1)
	}
}

// dbFlag registers -data-dir and -db and returns a function that resolves the
// database path once flags are parsed. Precedence: -db, -data-dir,
// $GH_APPAUTH_BROKER_DB, $GH_APPAUTH_BROKER_DATA_DIR, then data/ next to the
// binary.
func dbFlag(fs *flag.FlagSet) func() (string, error) {
	dataDir := fs.String("data-dir", "", "`directory` holding broker.db (env GH_APPAUTH_BROKER_DATA_DIR; default: data/ next to the binary)")
	db := fs.String("db", "", "SQLite database `file`, overrides -data-dir (env GH_APPAUTH_BROKER_DB)")
	return func() (string, error) {
		switch {
		case *db != "":
			return *db, nil
		case *dataDir != "":
			return filepath.Join(*dataDir, "broker.db"), nil
		}
		if v := os.Getenv("GH_APPAUTH_BROKER_DB"); v != "" {
			return v, nil
		}
		if v := os.Getenv("GH_APPAUTH_BROKER_DATA_DIR"); v != "" {
			return filepath.Join(v, "broker.db"), nil
		}
		dir, err := defaultDataDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "broker.db"), nil
	}
}

func defaultDataDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the broker binary for the default data directory (pass -data-dir): %w", err)
	}
	// Resolve symlinks so a link in /usr/local/bin still finds the data next to
	// the real binary.
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Join(filepath.Dir(exe), "data"), nil
}

type serveConfig struct {
	DB             string
	Listen         string
	UIListen       string
	TLSMode        string
	TLSCert        string
	TLSKey         string
	TLSHosts       string
	TrustedProxies string
	GitHubAPI      string
	HistoryDays    int
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var c serveConfig
	db := dbFlag(fs)
	fs.StringVar(&c.Listen, "listen", ":8443", "API `address` (host:port or unix:/path)")
	fs.StringVar(&c.UIListen, "ui-listen", "", "admin UI `address`: empty = serve /ui/ on the API listener, \"off\" = disabled, or host:port for a separate listener")
	fs.StringVar(&c.TLSMode, "tls", tlsSelf, "TLS `mode`: self (generated self-signed cert), files (-tls-cert/-tls-key), or off")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "certificate chain PEM `file` for -tls files")
	fs.StringVar(&c.TLSKey, "tls-key", "", "private key PEM `file` for -tls files")
	fs.StringVar(&c.TLSHosts, "tls-hosts", "", "comma-separated hostnames/IPs for the self-signed certificate (default: localhost, hostname, interface IPs)")
	fs.StringVar(&c.TrustedProxies, "trusted-proxies", "", "comma-separated `CIDRs` of reverse proxies whose X-Forwarded-For is trusted")
	fs.StringVar(&c.GitHubAPI, "github-api", "https://api.github.com", "GitHub API base `URL`")
	fs.IntVar(&c.HistoryDays, "history-days", 30, "keep request history for this many `days`")
	fs.Parse(args)
	var err error
	if c.DB, err = db(); err != nil {
		return err
	}
	return serve(c, nil)
}

func isLoopback(addr string) bool {
	if strings.HasPrefix(addr, "unix:") {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func listen(addr string) (net.Listener, error) {
	if p, ok := strings.CutPrefix(addr, "unix:"); ok {
		return listenUnix(p)
	}
	return net.Listen("tcp", addr)
}

// listenUnix binds the socket inside a private directory, sets its mode and
// only then moves it to p, so it is never reachable with the wider
// permissions the umask would give it.
func listenUnix(p string) (net.Listener, error) {
	dir, err := os.MkdirTemp(filepath.Dir(p), ".sock-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, err
	}
	// The listener would otherwise try to remove tmp, not p, when it closes.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err = os.Chmod(tmp, 0o660); err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// setupURL guesses the URL clients should use, for display in the UI.
func setupURL(listenAddr, mode string) string {
	scheme := "https"
	if mode == tlsOff {
		scheme = "http"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return scheme + "://BROKER-HOST"
	}
	if ip, err := netip.ParseAddr(host); host == "" || (err == nil && ip.IsUnspecified()) {
		if h, err := os.Hostname(); err == nil && h != "" {
			host = h
		} else {
			host = "BROKER-HOST"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// serve runs the broker until SIGINT/SIGTERM. ready, if non-nil, receives the
// bound API address once listening (used by tests).
func serve(c serveConfig, ready chan<- string) error {
	switch c.TLSMode {
	case tlsOff, tlsSelf, tlsFiles:
	default:
		return fmt.Errorf("-tls must be self, files or off (got %q)", c.TLSMode)
	}
	var trusted []netip.Prefix
	if c.TrustedProxies != "" {
		var err error
		if trusted, err = parseCIDRs(strings.Split(c.TrustedProxies, ",")); err != nil {
			return fmt.Errorf("-trusted-proxies: %w", err)
		}
	}
	st, err := OpenStore(c.DB)
	if err != nil {
		return err
	}
	defer st.Close()

	var certs *certSource
	var hosts []string
	switch c.TLSMode {
	case tlsSelf:
		explicit := c.TLSHosts != ""
		hosts = defaultHosts()
		if explicit {
			hosts = splitList(c.TLSHosts)
		}
		if certs, err = newSelfCertSource(st, hosts, explicit); err != nil {
			return fmt.Errorf("self-signed certificate: %w", err)
		}
		if leaf, err := x509.ParseCertificate(certs.cert.Certificate[0]); err == nil {
			hosts = append(leaf.DNSNames, ipStrings(leaf.IPAddresses)...)
		}
	case tlsFiles:
		if certs, err = newFileCertSource(c.TLSCert, c.TLSKey); err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
	case tlsOff:
		for _, a := range []string{c.Listen, c.UIListen} {
			if a != "" && a != "off" && !isLoopback(a) {
				fmt.Fprintf(os.Stderr, "gh-appauth-broker: WARNING: TLS is off and %s is not loopback; client secrets, tokens and the admin password travel unencrypted. Only do this on a network you trust.\n", a)
			}
		}
	}

	info := ServerInfo{DBPath: c.DB, Listen: c.Listen, UIListen: c.UIListen, TLSMode: c.TLSMode, TLSHosts: hosts, SetupURL: setupURL(c.Listen, c.TLSMode)}
	if certs != nil {
		info.TLSFingerprint = certs.fingerprint()
	}
	for _, p := range trusted {
		info.TrustedProxies = append(info.TrustedProxies, p.String())
	}
	b, err := NewBroker(st, Options{
		GitHubAPI: c.GitHubAPI, TrustedProxies: trusted, HistoryDays: c.HistoryDays,
		SecureCookies: certs != nil, Info: info,
	})
	if err != nil {
		return fmt.Errorf("invalid configuration in %s: %w", c.DB, err)
	}
	if pw, _ := st.GetSetting("admin_password"); pw == "" && c.UIListen != "off" {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: no admin password set; run `gh-appauth-broker set-password -db %s` to use the web UI\n", c.DB)
	}

	newServer := func(h http.Handler) *http.Server {
		s := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second, // must exceed githubBudget
			IdleTimeout:       120 * time.Second,
			ErrorLog:          nil,
		}
		if certs != nil {
			s.TLSConfig = certs.tlsConfig()
		}
		return s
	}
	type srv struct {
		s    *http.Server
		ln   net.Listener
		name string
	}
	var servers []srv
	sharedUI := c.UIListen == ""
	ln, err := listen(c.Listen)
	if err != nil {
		return err
	}
	servers = append(servers, srv{newServer(b.APIHandler(sharedUI)), ln, "API"})
	if c.UIListen != "" && c.UIListen != "off" {
		uln, err := listen(c.UIListen)
		if err != nil {
			ln.Close()
			return err
		}
		servers = append(servers, srv{newServer(b.UIHandler()), uln, "admin UI"})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.PruneLoop(ctx)

	errc := make(chan error, len(servers))
	scheme := "http"
	if certs != nil {
		scheme = "https"
	}
	for _, s := range servers {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: %s listening on %s://%s\n", s.name, scheme, s.ln.Addr())
		go func(s srv) {
			var err error
			if certs != nil {
				err = s.s.ServeTLS(s.ln, "", "")
			} else {
				err = s.s.Serve(s.ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s server: %w", s.name, err)
			}
		}(s)
	}
	if sharedUI {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: admin UI at %s://%s/ui/\n", scheme, ln.Addr())
	}
	if certs != nil {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: TLS certificate SHA-256 fingerprint: %s\n", info.TLSFingerprint)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	if ready != nil {
		addrs := []string{}
		for _, s := range servers {
			addrs = append(addrs, s.ln.Addr().String())
		}
		ready <- strings.Join(addrs, " ")
	}
	for {
		select {
		case err := <-errc:
			return err
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				if err := b.Reload(); err != nil {
					fmt.Fprintf(os.Stderr, "gh-appauth-broker: reload failed, keeping previous configuration: %v\n", err)
				} else {
					fmt.Fprintln(os.Stderr, "gh-appauth-broker: configuration reloaded")
				}
				if certs != nil {
					if err := certs.reload(); err != nil {
						fmt.Fprintf(os.Stderr, "gh-appauth-broker: certificate reload failed, keeping previous: %v\n", err)
					}
				}
				continue
			}
			fmt.Fprintln(os.Stderr, "gh-appauth-broker: shutting down")
			sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer scancel()
			for _, s := range servers {
				_ = s.s.Shutdown(sctx)
			}
			return nil
		}
	}
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dbPath := dbFlag(fs)
	fs.Parse(args)
	db, err := dbPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(db); err != nil {
		return err
	}
	st, err := OpenStore(db)
	if err != nil {
		return err
	}
	defer st.Close()
	rows, err := st.LoadConfig()
	if err != nil {
		return err
	}
	if _, err := buildState(rows); err != nil {
		return err
	}
	pw, _ := st.GetSetting("admin_password")
	fmt.Printf("ok: %d app(s), %d client(s), %d secret(s), %d grant(s); admin password set: %v\n",
		len(rows.Apps), len(rows.Clients), len(rows.Secrets), len(rows.Grants), pw != "")
	return nil
}

func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	dbPath := dbFlag(fs)
	certFile := fs.String("tls-cert", "", "print the fingerprint of this certificate file instead")
	fs.Parse(args)
	var certPEM []byte
	if *certFile != "" {
		b, err := os.ReadFile(*certFile)
		if err != nil {
			return err
		}
		certPEM = b
	} else {
		db, err := dbPath()
		if err != nil {
			return err
		}
		st, err := OpenStore(db)
		if err != nil {
			return err
		}
		defer st.Close()
		s, _ := st.GetSetting("tls_self_cert")
		if s == "" {
			return errors.New("no self-signed certificate yet; start the broker with -tls self first")
		}
		certPEM = []byte(s)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("no PEM certificate found")
	}
	fmt.Println(certFingerprint(block.Bytes))
	return nil
}

func cmdSetPassword(args []string) error {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	dbPath := dbFlag(fs)
	fs.Parse(args)
	db, err := dbPath()
	if err != nil {
		return err
	}
	pw, err := readPassword("New admin password: ")
	if err != nil {
		return err
	}
	if isTerminal(os.Stdin) {
		again, err := readPassword("Repeat: ")
		if err != nil {
			return err
		}
		if again != pw {
			return errors.New("passwords do not match")
		}
	}
	if len(pw) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	st, err := OpenStore(db)
	if err != nil {
		return err
	}
	defer st.Close()
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	if err := st.SetSetting("admin_password", h); err != nil {
		return err
	}
	st.DeleteAllSessions()
	fmt.Fprintln(os.Stderr, "admin password set")
	return nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var stdinReader = bufio.NewReader(os.Stdin)

// readPassword reads one line from stdin, turning off echo with stty when
// stdin is a terminal.
func readPassword(prompt string) (string, error) {
	tty := isTerminal(os.Stdin)
	if tty {
		fmt.Fprint(os.Stderr, prompt)
		if err := stty("-echo"); err == nil {
			defer func() { stty("echo"); fmt.Fprintln(os.Stderr) }()
		}
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func stty(arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

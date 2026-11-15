// Command fakegithub serves the fake GitHub API used by scripts/e2e.sh.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/tbshfr/gh-appauth/internal/fakegithub"
)

type config struct {
	Apps []struct {
		ID             int64  `json:"id"`
		Slug           string `json:"slug"`
		BotID          int64  `json:"bot_id"`
		PrivateKeyFile string `json:"private_key_file"`
		Installations  []struct {
			ID          int64             `json:"id"`
			Owner       string            `json:"owner"`
			Repos       []string          `json:"repos"`
			Permissions map[string]string `json:"permissions"`
		} `json:"installations"`
	} `json:"apps"`
}

func publicKey(file string) *rsa.PublicKey {
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatalf("%s: no PEM", file)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &k.PublicKey
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("%s: %v", file, err)
	}
	return &k.(*rsa.PrivateKey).PublicKey
}

func main() {
	cfgFile := flag.String("config", "", "JSON config")
	addrFile := flag.String("addr-file", "", "write the listen address here")
	flag.Parse()
	b, err := os.ReadFile(*cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		log.Fatal(err)
	}
	var apps []*fakegithub.App
	for _, a := range c.Apps {
		app := &fakegithub.App{ID: a.ID, Slug: a.Slug, BotID: a.BotID, PublicKey: publicKey(a.PrivateKeyFile)}
		for _, in := range a.Installations {
			app.Installations = append(app.Installations, &fakegithub.Installation{ID: in.ID, Owner: in.Owner, Repos: in.Repos, Permissions: in.Permissions})
		}
		apps = append(apps, app)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "fakegithub listening on %s\n", ln.Addr())
	log.Fatal(http.Serve(ln, fakegithub.New(apps...)))
}

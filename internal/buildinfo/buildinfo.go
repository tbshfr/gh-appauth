// Package buildinfo reports which version a binary was built as.
package buildinfo

import (
	"regexp"
	"runtime/debug"
)

// Resolve returns stamped, the value set with -ldflags "-X main.version=...",
// when there is one. A plain `go build` or `go install` leaves it at "dev";
// Go then still records the module version from the VCS tag (or a
// pseudo-version), which beats reporting "dev".
func Resolve(stamped string) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

const releases = "https://github.com/tbshfr/gh-appauth/releases"

// ReleaseURL links to the GitHub release for v. Versions that aren't a
// release tag (dev builds, `git describe` output, pseudo-versions) have no
// release page of their own, so they get the list of releases.
func ReleaseURL(v string) string {
	if !releaseTag.MatchString(v) {
		return releases
	}
	return releases + "/tag/" + v
}

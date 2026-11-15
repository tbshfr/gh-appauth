// Package api holds the JSON types exchanged between the broker and the
// gh extension.
package api

import "time"

type TokenRequest struct {
	Repository  string            `json:"repository"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

type TokenResponse struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Repository  string            `json:"repository"`
	App         string            `json:"app"`
	Permissions map[string]string `json:"permissions"`
	BotName     string            `json:"bot_name,omitempty"`
	BotEmail    string            `json:"bot_email,omitempty"`
	Cached      bool              `json:"cached"`
}

// InvalidateRequest tells the broker that GitHub rejected a token it issued,
// so the broker must not hand it out again from its cache.
type InvalidateRequest struct {
	Token string `json:"token"`
}

type Grant struct {
	App         string            `json:"app"`
	Repos       []string          `json:"repos"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

type WhoAmI struct {
	Client string  `json:"client"`
	IP     string  `json:"ip"`
	Grants []Grant `json:"grants"`
}

type Error struct {
	Error string `json:"error"`
}

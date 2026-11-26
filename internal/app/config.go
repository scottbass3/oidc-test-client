package app

import (
	"encoding/json"
	"os"
	"slices"
	"sync"
)

type Config struct {
	IssuerURL        string `json:"issuer_url"`
	AuthorizationURL string `json:"authorization_url"`
	TokenURL         string `json:"token_url"`
	UserinfoURL      string `json:"userinfo_url"`
	IntrospectionURL string `json:"introspection_url"`
	JWKSURI          string `json:"jwks_uri"`
	EndSessionURL    string `json:"end_session_url"`

	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	RedirectURI           string `json:"redirect_uri"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`

	Scopes       []string `json:"scopes"`
	ResponseType string   `json:"response_type"`
	ResponseMode string   `json:"response_mode"`

	PKCEEnabled bool   `json:"pkce_enabled"`
	PKCEMethod  string `json:"pkce_method"`

	ExtraAuthorizeParams map[string]string `json:"extra_authorize_params"`
	ExtraTokenParams     map[string]string `json:"extra_token_params"`
}

func defaultConfig() Config {
	return Config{
		Scopes:               []string{"openid", "profile", "email"},
		ResponseType:         "code",
		PKCEMethod:           "S256",
		ExtraAuthorizeParams: map[string]string{},
		ExtraTokenParams:     map[string]string{},
	}
}

type ConfigStore struct {
	mu       sync.RWMutex
	config   Config
	filepath string
}

// NewConfigStore reads the configuration from the file, then the environment.
// Locked, the file is left out: the provider and the client come from the
// environment only.
func NewConfigStore(filepath string, locked bool) *ConfigStore {
	cs := &ConfigStore{
		config:   defaultConfig(),
		filepath: filepath,
	}
	if !locked {
		cs.loadFromFile()
	}
	cs.loadFromEnv()
	return cs
}

// setTunables copies from from the settings a tester tunes in locked mode,
// the ones that are not part of the provider or of the client's registration.
func (c *Config) setTunables(from Config) {
	c.Scopes = from.Scopes
	c.ResponseType = from.ResponseType
	c.ResponseMode = from.ResponseMode
	c.PKCEEnabled = from.PKCEEnabled
	c.PKCEMethod = from.PKCEMethod
	c.ExtraAuthorizeParams = from.ExtraAuthorizeParams
	c.ExtraTokenParams = from.ExtraTokenParams
}

// In locked mode the extra parameters leave alone what the client sets itself
// in a request: the client and its redirect URI, what ties the request to the
// session and, at the token endpoint, the grant, which would otherwise let a
// tester ask for one in the client's own name.
var (
	fixedAuthorizeParams = []string{"client_id", "redirect_uri", "state", "nonce"}
	fixedTokenParams     = []string{"client_id", "client_secret", "client_assertion", "client_assertion_type",
		"redirect_uri", "grant_type", "code", "refresh_token"}
)

// withoutParams returns extra without the parameters named by fixed.
func withoutParams(extra map[string]string, fixed []string) map[string]string {
	out := make(map[string]string, len(extra))
	for k, v := range extra {
		if !slices.Contains(fixed, k) {
			out[k] = v
		}
	}
	return out
}

// lockedChange names the first field of posted that locked mode refuses, ""
// when there is none: a provider endpoint or a client field that differs from
// the fixed one, any client secret, so that the answer does not tell whether
// a guess is right, or an extra parameter that would replace one the client
// sets itself. An empty field asks for no change.
func lockedChange(posted, fixed Config) string {
	if posted.ClientSecret != "" {
		return "client_secret"
	}
	for _, f := range []struct{ name, posted, fixed string }{
		{"issuer_url", posted.IssuerURL, fixed.IssuerURL},
		{"authorization_url", posted.AuthorizationURL, fixed.AuthorizationURL},
		{"token_url", posted.TokenURL, fixed.TokenURL},
		{"userinfo_url", posted.UserinfoURL, fixed.UserinfoURL},
		{"introspection_url", posted.IntrospectionURL, fixed.IntrospectionURL},
		{"jwks_uri", posted.JWKSURI, fixed.JWKSURI},
		{"end_session_url", posted.EndSessionURL, fixed.EndSessionURL},
		{"client_id", posted.ClientID, fixed.ClientID},
		{"redirect_uri", posted.RedirectURI, fixed.RedirectURI},
		{"post_logout_redirect_uri", posted.PostLogoutRedirectURI, fixed.PostLogoutRedirectURI},
	} {
		if f.posted != "" && f.posted != f.fixed {
			return f.name
		}
	}
	for _, e := range []struct {
		name  string
		extra map[string]string
		fixed []string
	}{
		{"extra_authorize_params", posted.ExtraAuthorizeParams, fixedAuthorizeParams},
		{"extra_token_params", posted.ExtraTokenParams, fixedTokenParams},
	} {
		for _, k := range e.fixed {
			if _, ok := e.extra[k]; ok {
				return e.name + "." + k
			}
		}
	}
	return ""
}

func (cs *ConfigStore) Get() Config {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.config
}

func (cs *ConfigStore) Set(c Config) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.config = c
	cs.saveToFile()
}

func (cs *ConfigStore) loadFromEnv() {
	if v := os.Getenv("OIDC_ISSUER_URL"); v != "" {
		cs.config.IssuerURL = v
	}
	if v := os.Getenv("OIDC_CLIENT_ID"); v != "" {
		cs.config.ClientID = v
	}
	if v := os.Getenv("OIDC_CLIENT_SECRET"); v != "" {
		cs.config.ClientSecret = v
	}
	if v := os.Getenv("OIDC_REDIRECT_URI"); v != "" {
		cs.config.RedirectURI = v
	}
	if v := os.Getenv("OIDC_AUTH_URL"); v != "" {
		cs.config.AuthorizationURL = v
	}
	if v := os.Getenv("OIDC_TOKEN_URL"); v != "" {
		cs.config.TokenURL = v
	}
	if v := os.Getenv("OIDC_USERINFO_URL"); v != "" {
		cs.config.UserinfoURL = v
	}
	if v := os.Getenv("OIDC_INTROSPECTION_URL"); v != "" {
		cs.config.IntrospectionURL = v
	}
	if v := os.Getenv("OIDC_JWKS_URI"); v != "" {
		cs.config.JWKSURI = v
	}
	if v := os.Getenv("OIDC_END_SESSION_URL"); v != "" {
		cs.config.EndSessionURL = v
	}
	if v := os.Getenv("OIDC_POST_LOGOUT_REDIRECT_URI"); v != "" {
		cs.config.PostLogoutRedirectURI = v
	}
}

func (cs *ConfigStore) loadFromFile() {
	data, err := os.ReadFile(cs.filepath)
	if err != nil {
		return
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return
	}
	cs.config = c
	if cs.config.ExtraAuthorizeParams == nil {
		cs.config.ExtraAuthorizeParams = map[string]string{}
	}
	if cs.config.ExtraTokenParams == nil {
		cs.config.ExtraTokenParams = map[string]string{}
	}
}

func (cs *ConfigStore) saveToFile() {
	data, err := json.MarshalIndent(cs.config, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(cs.filepath, data, 0600)
}

package app

import (
	"encoding/json"
	"os"
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

	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`

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

func NewConfigStore(filepath string) *ConfigStore {
	cs := &ConfigStore{
		config:   defaultConfig(),
		filepath: filepath,
	}
	cs.loadFromFile()
	cs.loadFromEnv()
	return cs
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

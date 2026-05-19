package app

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) registerRoutes() {
	staticFS, _ := fs.Sub(s.staticFS, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	s.mux.Handle("/", fileServer)

	s.mux.HandleFunc("/api/config", s.handleConfig)
	s.mux.HandleFunc("/api/discover", s.handleDiscover)
	s.mux.HandleFunc("/api/authorize-url", s.handleAuthorizeURL)
	s.mux.HandleFunc("/api/pkce/generate", s.handlePKCEGenerate)
	s.mux.HandleFunc("/api/token/exchange", s.handleTokenExchange)
	s.mux.HandleFunc("/api/token/refresh", s.handleTokenRefresh)
	s.mux.HandleFunc("/api/userinfo", s.handleUserInfo)
	s.mux.HandleFunc("/api/introspect", s.handleIntrospect)
	s.mux.HandleFunc("/api/jwt/decode", s.handleJWTDecode)
	s.mux.HandleFunc("/api/history", s.handleHistory)
	s.mux.HandleFunc("/auth/start", s.handleAuthStart)
	s.mux.HandleFunc("/auth/callback", s.handleAuthCallback)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- Config ---

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, s.config.Get())
	case http.MethodPost:
		var c Config
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if c.ExtraAuthorizeParams == nil {
			c.ExtraAuthorizeParams = map[string]string{}
		}
		if c.ExtraTokenParams == nil {
			c.ExtraTokenParams = map[string]string{}
		}
		s.config.Set(c)
		writeJSON(w, 200, s.config.Get())
	default:
		w.WriteHeader(405)
	}
}

// --- Discovery ---

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	var req struct {
		IssuerURL    string `json:"issuer_url"`
		UpdateConfig bool   `json:"update_config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	result, doc, _ := discover(req.IssuerURL)

	if doc != nil && req.UpdateConfig {
		cfg := s.config.Get()
		if doc.AuthorizationEndpoint != "" {
			cfg.AuthorizationURL = doc.AuthorizationEndpoint
		}
		if doc.TokenEndpoint != "" {
			cfg.TokenURL = doc.TokenEndpoint
		}
		if doc.UserinfoEndpoint != "" {
			cfg.UserinfoURL = doc.UserinfoEndpoint
		}
		if doc.IntrospectionEndpoint != "" {
			cfg.IntrospectionURL = doc.IntrospectionEndpoint
		}
		if doc.JWKSURI != "" {
			cfg.JWKSURI = doc.JWKSURI
		}
		if doc.EndSessionEndpoint != "" {
			cfg.EndSessionURL = doc.EndSessionEndpoint
		}
		s.config.Set(cfg)
	}

	writeJSON(w, 200, result)
}

// --- Authorize URL ---

type authorizeURLRequest struct {
	AuthorizationURL    string            `json:"authorization_url"`
	ClientID            string            `json:"client_id"`
	RedirectURI         string            `json:"redirect_uri"`
	Scopes              []string          `json:"scopes"`
	ResponseType        string            `json:"response_type"`
	ResponseMode        string            `json:"response_mode"`
	State               string            `json:"state"`
	Nonce               string            `json:"nonce"`
	CodeChallenge       string            `json:"code_challenge"`
	CodeChallengeMethod string            `json:"code_challenge_method"`
	CodeVerifier        string            `json:"code_verifier"` // stored server-side for callback
	ExtraParams         map[string]string `json:"extra_params"`
}

func (s *Server) handleAuthorizeURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	cfg := s.config.Get()
	var req authorizeURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	authURL := coalesce(req.AuthorizationURL, cfg.AuthorizationURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	redirectURI := coalesce(req.RedirectURI, cfg.RedirectURI)
	responseType := coalesce(req.ResponseType, cfg.ResponseType, "code")
	responseMode := coalesce(req.ResponseMode, cfg.ResponseMode)

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.Scopes
	}

	// Auto-generate state and nonce so the URL is always valid and the
	// callback can complete the flow even when "Open in Browser" is used.
	state := req.State
	if state == "" {
		var err error
		state, err = generateRandom(16)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to generate state: " + err.Error()})
			return
		}
	}
	nonce := req.Nonce
	if nonce == "" {
		var err error
		nonce, err = generateRandom(16)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to generate nonce: " + err.Error()})
			return
		}
	}

	// Register the state so /auth/callback can complete the exchange.
	s.flowMu.Lock()
	s.flowStates[state] = &FlowState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: req.CodeVerifier,
		CreatedAt:    time.Now(),
	}
	s.flowMu.Unlock()

	params := url.Values{}
	params.Set("response_type", responseType)
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)
	params.Set("nonce", nonce)

	if responseMode != "" {
		params.Set("response_mode", responseMode)
	}
	if req.CodeChallenge != "" {
		params.Set("code_challenge", req.CodeChallenge)
		method := coalesce(req.CodeChallengeMethod, "S256")
		params.Set("code_challenge_method", method)
	}

	for k, v := range cfg.ExtraAuthorizeParams {
		params.Set(k, v)
	}
	for k, v := range req.ExtraParams {
		params.Set(k, v)
	}

	writeJSON(w, 200, map[string]interface{}{
		"url":    authURL + "?" + params.Encode(),
		"params": params,
		"state":  state,
		"nonce":  nonce,
	})
}

// --- PKCE Generate ---

func (s *Server) handlePKCEGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	var req struct {
		Method string `json:"method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	method := coalesce(req.Method, "S256")

	verifier, err := generateCodeVerifier()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	challenge := generateCodeChallenge(verifier, method)

	writeJSON(w, 200, map[string]string{
		"code_verifier":          verifier,
		"code_challenge":         challenge,
		"code_challenge_method":  method,
	})
}

// --- Token Exchange ---

type tokenExchangeRequest struct {
	TokenURL     string            `json:"token_url"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	Code         string            `json:"code"`
	RedirectURI  string            `json:"redirect_uri"`
	CodeVerifier string            `json:"code_verifier"`
	ExtraParams  map[string]string `json:"extra_params"`
}

func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	cfg := s.config.Get()
	var req tokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	tokenURL := coalesce(req.TokenURL, cfg.TokenURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	clientSecret := coalesce(req.ClientSecret, cfg.ClientSecret)
	redirectURI := coalesce(req.RedirectURI, cfg.RedirectURI)

	extra := mergeParams(cfg.ExtraTokenParams, req.ExtraParams)

	result := exchangeCode(tokenURL, clientID, clientSecret, req.Code, redirectURI, req.CodeVerifier, extra)
	writeJSON(w, 200, result)
}

// --- Token Refresh ---

type tokenRefreshRequest struct {
	TokenURL     string            `json:"token_url"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	RefreshToken string            `json:"refresh_token"`
	ExtraParams  map[string]string `json:"extra_params"`
}

func (s *Server) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	cfg := s.config.Get()
	var req tokenRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	tokenURL := coalesce(req.TokenURL, cfg.TokenURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	clientSecret := coalesce(req.ClientSecret, cfg.ClientSecret)

	extra := mergeParams(cfg.ExtraTokenParams, req.ExtraParams)

	result := refreshToken(tokenURL, clientID, clientSecret, req.RefreshToken, extra)
	writeJSON(w, 200, result)
}

// --- UserInfo ---

type userInfoRequest struct {
	UserinfoURL string `json:"userinfo_url"`
	AccessToken string `json:"access_token"`
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	cfg := s.config.Get()
	var req userInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	userinfoURL := coalesce(req.UserinfoURL, cfg.UserinfoURL)
	result := getUserInfo(userinfoURL, req.AccessToken)
	writeJSON(w, 200, result)
}

// --- Introspect ---

type introspectRequest struct {
	IntrospectionURL string `json:"introspection_url"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	Token            string `json:"token"`
	TokenTypeHint    string `json:"token_type_hint"`
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	cfg := s.config.Get()
	var req introspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	introspectionURL := coalesce(req.IntrospectionURL, cfg.IntrospectionURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	clientSecret := coalesce(req.ClientSecret, cfg.ClientSecret)

	result := introspectToken(introspectionURL, clientID, clientSecret, req.Token, req.TokenTypeHint)
	writeJSON(w, 200, result)
}

// --- JWT Decode ---

func (s *Server) handleJWTDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	decoded, err := decodeJWT(req.Token)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, decoded)
}

// --- Full Auth Flow ---

func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	cfg := s.config.Get()

	if cfg.AuthorizationURL == "" {
		http.Error(w, "authorization_url not configured", 400)
		return
	}
	if cfg.ClientID == "" {
		http.Error(w, "client_id not configured", 400)
		return
	}
	if cfg.RedirectURI == "" {
		http.Error(w, "redirect_uri not configured", 400)
		return
	}

	state, err := generateRandom(16)
	if err != nil {
		http.Error(w, "failed to generate state", 500)
		return
	}
	nonce, err := generateRandom(16)
	if err != nil {
		http.Error(w, "failed to generate nonce", 500)
		return
	}

	flowState := &FlowState{
		State:     state,
		Nonce:     nonce,
		CreatedAt: time.Now(),
	}

	params := url.Values{}
	params.Set("response_type", coalesce(cfg.ResponseType, "code"))
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", cfg.RedirectURI)
	params.Set("scope", strings.Join(cfg.Scopes, " "))
	params.Set("state", state)
	params.Set("nonce", nonce)

	if cfg.ResponseMode != "" {
		params.Set("response_mode", cfg.ResponseMode)
	}

	if cfg.PKCEEnabled {
		verifier, err := generateCodeVerifier()
		if err != nil {
			http.Error(w, "failed to generate PKCE verifier", 500)
			return
		}
		challenge := generateCodeChallenge(verifier, cfg.PKCEMethod)
		flowState.CodeVerifier = verifier
		flowState.CodeChallenge = challenge
		params.Set("code_challenge", challenge)
		params.Set("code_challenge_method", cfg.PKCEMethod)
	}

	for k, v := range cfg.ExtraAuthorizeParams {
		params.Set(k, v)
	}

	s.flowMu.Lock()
	s.flowStates[state] = flowState
	s.flowMu.Unlock()

	http.Redirect(w, r, cfg.AuthorizationURL+"?"+params.Encode(), http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if errStr := q.Get("error"); errStr != "" {
		desc := q.Get("error_description")
		renderCallbackError(w, fmt.Sprintf("%s: %s", errStr, desc))
		return
	}

	state := q.Get("state")
	code := q.Get("code")

	s.flowMu.Lock()
	flowState, ok := s.flowStates[state]
	if ok {
		delete(s.flowStates, state)
	}
	s.flowMu.Unlock()

	if !ok {
		renderCallbackError(w, "invalid or expired state parameter")
		return
	}

	cfg := s.config.Get()
	extra := mergeParams(cfg.ExtraTokenParams, nil)

	result := exchangeCode(cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, code, cfg.RedirectURI, flowState.CodeVerifier, extra)
	id := s.addHistory(result)
	http.Redirect(w, r, "/?flow="+id, http.StatusFound)
}

// --- History ---

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}

	id := r.URL.Query().Get("id")

	s.historyMu.RLock()
	defer s.historyMu.RUnlock()

	if id != "" {
		for _, e := range s.history {
			if e.ID == id {
				writeJSON(w, 200, e)
				return
			}
		}
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}

	// Newest first
	out := make([]*HistoryEntry, len(s.history))
	for i, e := range s.history {
		out[len(s.history)-1-i] = e
	}
	writeJSON(w, 200, out)
}

func renderCallbackError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(400)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Auth Error</title>
<style>
*{box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:2rem;margin:0}
.error{color:#f85149;background:#1c1010;border:1px solid #f85149;padding:1rem;border-radius:6px}
a{color:#58a6ff}
</style>
</head>
<body>
<h2>Authentication Error</h2>
<div class="error">%s</div>
<p><a href="/">← Back to OIDC Test Client</a></p>
</body>
</html>`, msg)
}


// --- Helpers ---

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mergeParams(base, override map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range base {
		result[k] = v
	}
	for k, v := range override {
		result[k] = v
	}
	return result
}

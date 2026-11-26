package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
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
	s.mux.HandleFunc("/auth/logout", s.handleLogout)
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
		// The page reads the configuration first: locked, that is when the
		// browser gets its session, so that the requests it sends next, even
		// several at once, all come with the same cookie.
		sess, err := s.openSession(w, r)
		if err != nil {
			sess = s.session(r)
		}
		writeJSON(w, 200, s.configView(s.configFor(sess)))
	case http.MethodPost:
		if s.locked {
			s.saveSettings(w, r)
			return
		}
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
		writeJSON(w, 200, s.configView(s.config.Get()))
	default:
		w.WriteHeader(405)
	}
}

// saveSettings is the POST of the configuration in locked mode. The provider
// and the client are fixed: the settings go to the session, and nothing to
// the configuration or its file. A setting the body leaves out keeps its
// value.
func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	cur := s.configFor(s.session(r))
	// Decoded over the current settings, without the secret, that the body may
	// not carry, nor the slice and the maps, that decoding would write into.
	c := cur
	c.ClientSecret = ""
	c.Scopes, c.ExtraAuthorizeParams, c.ExtraTokenParams = nil, nil, nil
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if c.Scopes == nil {
		c.Scopes = cur.Scopes
	}
	if c.ExtraAuthorizeParams == nil {
		c.ExtraAuthorizeParams = cur.ExtraAuthorizeParams
	}
	if c.ExtraTokenParams == nil {
		c.ExtraTokenParams = cur.ExtraTokenParams
	}
	if field := lockedChange(c, s.config.Get()); field != "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": field + " is fixed in locked mode"})
		return
	}
	if err := s.checkResponseMode(c.ResponseMode); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	sess, err := s.openSession(w, r)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	sess.mu.Lock()
	sess.settings = &c
	sess.mu.Unlock()
	writeJSON(w, 200, s.configView(s.configFor(sess)))
}

// checkResponseMode refuses form_post in locked mode: the provider's POST
// comes from another site, so without the session cookie, which is
// SameSite=Lax, and its state could never be found.
func (s *Server) checkResponseMode(mode string) error {
	if s.locked && mode == "form_post" {
		return errors.New("response_mode form_post is not supported in locked mode: the callback would come without the session cookie")
	}
	return nil
}

// writeSessionError answers a request that could not open its session.
func writeSessionError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, errTooManySessions) {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]string{"error": "failed to open a session: " + err.Error()})
}

// authorizeExtras and tokenExtras return the extra parameters to send: locked,
// without those that would replace what the client sets itself.
func (s *Server) authorizeExtras(extra map[string]string) map[string]string {
	if !s.locked {
		return extra
	}
	return withoutParams(extra, fixedAuthorizeParams)
}

func (s *Server) tokenExtras(extra map[string]string) map[string]string {
	if !s.locked {
		return extra
	}
	return withoutParams(extra, fixedTokenParams)
}

// configView is the configuration as the browser gets it: locked says whether
// the provider and the client are fixed, and then the client secret is left
// out.
type configView struct {
	Config
	Locked bool `json:"locked"`
}

func (s *Server) configView(cfg Config) configView {
	if s.locked {
		cfg.ClientSecret = ""
	}
	return configView{Config: cfg, Locked: s.locked}
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

	if s.locked {
		req.IssuerURL = s.config.Get().IssuerURL
		req.UpdateConfig = false
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

	var req authorizeURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if s.locked {
		req.AuthorizationURL, req.ClientID, req.RedirectURI = "", "", ""
	}
	cfg := s.configFor(s.session(r))

	authURL := coalesce(req.AuthorizationURL, cfg.AuthorizationURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	redirectURI := coalesce(req.RedirectURI, cfg.RedirectURI)
	responseType := coalesce(req.ResponseType, cfg.ResponseType, "code")
	responseMode := coalesce(req.ResponseMode, cfg.ResponseMode)
	if err := s.checkResponseMode(responseMode); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

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
	sess, err := s.openSession(w, r)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	sess.addState(&FlowState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: req.CodeVerifier,
		CreatedAt:    time.Now(),
	})

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

	for k, v := range s.authorizeExtras(mergeParams(cfg.ExtraAuthorizeParams, req.ExtraParams)) {
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

	cfg := s.configFor(s.session(r))
	var req tokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if s.locked {
		req.TokenURL, req.ClientID, req.ClientSecret, req.RedirectURI = "", "", "", ""
	}

	tokenURL := coalesce(req.TokenURL, cfg.TokenURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	clientSecret := coalesce(req.ClientSecret, cfg.ClientSecret)
	redirectURI := coalesce(req.RedirectURI, cfg.RedirectURI)

	extra := s.tokenExtras(mergeParams(cfg.ExtraTokenParams, req.ExtraParams))

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

	cfg := s.configFor(s.session(r))
	var req tokenRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if s.locked {
		req.TokenURL, req.ClientID, req.ClientSecret = "", "", ""
	}

	tokenURL := coalesce(req.TokenURL, cfg.TokenURL)
	clientID := coalesce(req.ClientID, cfg.ClientID)
	clientSecret := coalesce(req.ClientSecret, cfg.ClientSecret)

	extra := s.tokenExtras(mergeParams(cfg.ExtraTokenParams, req.ExtraParams))

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
	if s.locked {
		req.UserinfoURL = ""
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
	if s.locked {
		req.IntrospectionURL, req.ClientID, req.ClientSecret = "", "", ""
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
	cfg := s.configFor(s.session(r))

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

	for k, v := range s.authorizeExtras(cfg.ExtraAuthorizeParams) {
		params.Set(k, v)
	}

	// The session opens last, once the request is known to start a flow.
	sess, err := s.openSession(w, r)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errTooManySessions) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "failed to open a session: "+err.Error(), status)
		return
	}
	sess.addState(flowState)

	http.Redirect(w, r, cfg.AuthorizationURL+"?"+params.Encode(), http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	// The answer is in the query, or in the form with response_mode=form_post.
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderCallbackError(w, "invalid callback form: "+err.Error())
			return
		}
		q = r.PostForm
	}

	if errStr := q.Get("error"); errStr != "" {
		desc := q.Get("error_description")
		renderCallbackError(w, fmt.Sprintf("%s: %s", errStr, desc))
		return
	}

	state := q.Get("state")
	code := q.Get("code")

	// The state has to be one this browser's session started: a callback
	// carrying the state of another session is refused.
	sess := s.session(r)
	flowState, ok := sess.takeState(state)
	if !ok {
		renderCallbackError(w, "invalid or expired state parameter")
		return
	}

	callbackParams := make(map[string]string)
	for k, vs := range q {
		if len(vs) > 0 {
			callbackParams[k] = vs[0]
		}
	}

	cfg := s.configFor(sess)
	extra := s.tokenExtras(cfg.ExtraTokenParams)

	result := exchangeCode(cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, code, cfg.RedirectURI, flowState.CodeVerifier, extra)
	id := sess.addHistory(result, callbackParams)
	http.Redirect(w, r, "/?flow="+id, http.StatusFound)
}

// --- Logout ---

// handleLogout starts an RP-initiated logout: the browser goes to the end
// session endpoint with the id_token of a flow of the session's history as
// id_token_hint, the flow named by flow, or the newest with an id_token.
// With a post-logout redirect URI configured, the provider sends the browser
// back there with the state, kept on the flow to check it.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin logout refused", http.StatusForbidden)
		return
	}
	sess := s.session(r)
	cfg := s.configFor(sess)

	if cfg.EndSessionURL == "" {
		renderCallbackError(w, "end_session_url not configured")
		return
	}
	endSession, err := url.Parse(cfg.EndSessionURL)
	if err != nil {
		renderCallbackError(w, "invalid end_session_url: "+err.Error())
		return
	}
	var state string
	if cfg.PostLogoutRedirectURI != "" {
		if state, err = generateRandom(16); err != nil {
			http.Error(w, "failed to generate state", 500)
			return
		}
	}
	idToken, err := sess.markLogout(r.FormValue("flow"), state, time.Now())
	if err != nil {
		renderCallbackError(w, err.Error())
		return
	}

	params := endSession.Query()
	params.Set("id_token_hint", idToken)
	if state != "" {
		params.Set("post_logout_redirect_uri", cfg.PostLogoutRedirectURI)
		params.Set("state", state)
	}
	endSession.RawQuery = params.Encode()

	http.Redirect(w, r, endSession.String(), http.StatusFound)
}

// sameOrigin reports whether r comes from a page of this client. Browsers send
// Sec-Fetch-Site, older ones only Origin; a request with neither is not a
// cross-site browser request.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

// markLogout returns the id_token of the history entry id, or, id empty, of
// the newest entry that has one, and notes on that entry the logout sent at
// at with state.
func (sess *session) markLogout(id, state string, at time.Time) (string, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	for i := len(sess.history) - 1; i >= 0; i-- {
		e := sess.history[i]
		if id != "" && e.ID != id {
			continue
		}
		t := idTokenOfResult(e.Result)
		if t == "" {
			if id != "" {
				return "", fmt.Errorf("flow %s has no id_token", id)
			}
			continue
		}
		e.LoggedOutAt = &at
		e.LogoutState = state
		return t, nil
	}
	if id != "" {
		return "", fmt.Errorf("flow %s is not in the history, which keeps the last %d", id, maxHistory)
	}
	return "", fmt.Errorf("no id_token in the history to log out with")
}

// idTokenClaims returns the unverified payload of an id_token, nil without one.
func idTokenClaims(token string) map[string]interface{} {
	if token == "" {
		return nil
	}
	jwt, err := decodeJWT(token)
	if err != nil {
		return nil
	}
	claims, _ := jwt["payload"].(map[string]interface{})
	return claims
}

// idTokenOfResult returns the id_token of a token response, "" without one.
func idTokenOfResult(res *OIDCResult) string {
	if res == nil || res.Response == nil {
		return ""
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(res.Response.Body), &body); err != nil {
		return ""
	}
	return body.IDToken
}

// --- History ---

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}

	id := r.URL.Query().Get("id")

	sess := s.session(r)
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if id != "" {
		for _, e := range sess.history {
			if e.ID == id {
				writeJSON(w, 200, e)
				return
			}
		}
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}

	// Newest first
	out := make([]*HistoryEntry, len(sess.history))
	for i, e := range sess.history {
		out[len(sess.history)-1-i] = e
	}
	writeJSON(w, 200, out)
}

func renderCallbackError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(400)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Auth Error</title>
<link rel="stylesheet" href="/style.css">
</head>
<body class="error-page">
<h2>Authentication Error</h2>
<div class="error-box">%s</div>
<p><a href="/">← Back to OIDC Test Client</a></p>
</body>
</html>`, html.EscapeString(msg))
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

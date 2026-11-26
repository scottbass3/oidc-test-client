package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const lockedSecret = "s3cret-from-env"

// provider is a fake OIDC provider that notes the requests it gets, as
// "path user:password", the client credentials sent with them.
type provider struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	p := &provider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		p.mu.Lock()
		p.hits = append(p.hits, r.URL.Path+" "+user+":"+pass)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			// The id_token names the code, to tell the flows apart.
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "id-" + r.Form.Get("code"), "access_token": "at"})
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "https://discovered.example/token"})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *provider) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hits...)
}

// newLockedServer returns a locked server whose provider and client come from
// the environment, next to a config file that names others, to be ignored.
func newLockedServer(t *testing.T, p *provider) *Server {
	t.Helper()
	for k, v := range map[string]string{
		"OIDC_ISSUER_URL":               p.URL,
		"OIDC_AUTH_URL":                 p.URL + "/auth",
		"OIDC_TOKEN_URL":                p.URL + "/token",
		"OIDC_USERINFO_URL":             p.URL + "/userinfo",
		"OIDC_INTROSPECTION_URL":        p.URL + "/introspect",
		"OIDC_END_SESSION_URL":          p.URL + "/logout",
		"OIDC_JWKS_URI":                 "",
		"OIDC_CLIENT_ID":                "client",
		"OIDC_CLIENT_SECRET":            lockedSecret,
		"OIDC_REDIRECT_URI":             "https://rp.example/auth/callback",
		"OIDC_POST_LOGOUT_REDIRECT_URI": "",
	} {
		t.Setenv(k, v)
	}
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, []byte(`{"token_url":"https://file.example/token","jwks_uri":"https://file.example/jwks","client_secret":"from-file"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return New(Options{StaticFS: fstest.MapFS{}, ConfigFile: file, Locked: true})
}

// browser sends requests to a server and keeps its session cookie, as a
// browser would.
type browser struct {
	t      *testing.T
	s      *Server
	cookie *http.Cookie
}

func (b *browser) do(method, target, body string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if strings.HasPrefix(body, "{") {
		req.Header.Set("Content-Type", "application/json")
	} else if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if b.cookie != nil {
		req.AddCookie(b.cookie)
	}
	rec := httptest.NewRecorder()
	b.s.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			b.cookie = c
		}
	}
	return rec
}

// json sends a request and decodes the JSON answer into out, checking the
// status.
func (b *browser) json(method, target, body string, status int, out interface{}) {
	b.t.Helper()
	rec := b.do(method, target, body)
	if rec.Code != status {
		b.t.Fatalf("%s %s: status %d, want %d: %s", method, target, rec.Code, status, rec.Body)
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			b.t.Fatalf("%s %s: %v: %s", method, target, err, rec.Body)
		}
	}
}

// start starts a flow and returns the state sent to the provider.
func (b *browser) start() string {
	b.t.Helper()
	rec := b.do(http.MethodGet, "/auth/start", "")
	if rec.Code != http.StatusFound {
		b.t.Fatalf("/auth/start: status %d: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	return loc.Query().Get("state")
}

// flow runs a whole flow with code and returns the id of its history entry.
func (b *browser) flow(code string) string {
	b.t.Helper()
	rec := b.do(http.MethodGet, "/auth/callback?code="+code+"&state="+url.QueryEscape(b.start()), "")
	if rec.Code != http.StatusFound {
		b.t.Fatalf("/auth/callback: status %d: %s", rec.Code, rec.Body)
	}
	return strings.TrimPrefix(rec.Header().Get("Location"), "/?flow=")
}

func (b *browser) history() []HistoryEntry {
	b.t.Helper()
	var entries []HistoryEntry
	b.json(http.MethodGet, "/api/history", "", 200, &entries)
	return entries
}

func TestLockedSecondBrowser(t *testing.T) {
	p := newProvider(t)
	s := newLockedServer(t, p)
	alice, bob := &browser{t: t, s: s}, &browser{t: t, s: s}

	id := alice.flow("alice")
	if h := alice.history(); len(h) != 1 || h[0].ID != id {
		t.Fatalf("alice's history %+v, want her flow %s", h, id)
	}
	c := alice.cookie
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || len(c.Value) < 32 {
		t.Errorf("session cookie %+v, want a random one, HttpOnly, Secure, SameSite=Lax, on /", c)
	}

	// The second browser: an empty history, no secret, and not alice's flow
	// even by its id.
	if h := bob.history(); len(h) != 0 {
		t.Errorf("bob's history %+v, want it empty", h)
	}
	if rec := bob.do(http.MethodGet, "/api/history?id="+id, ""); rec.Code != http.StatusNotFound {
		t.Errorf("bob reads alice's flow: status %d, want 404: %s", rec.Code, rec.Body)
	}
	if bob.cookie != nil {
		t.Errorf("reading opened a session: %+v", bob.cookie)
	}
	for _, b := range []*browser{alice, bob} {
		rec := b.do(http.MethodGet, "/api/config", "")
		var cfg configView
		if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
			t.Fatal(err)
		}
		if !cfg.Locked || cfg.ClientID != "client" || cfg.TokenURL != p.URL+"/token" {
			t.Errorf("config %+v, want it locked, with the client and the provider of the environment", cfg)
		}
		if strings.Contains(rec.Body.String(), lockedSecret) || cfg.ClientSecret != "" {
			t.Errorf("config gives the secret away: %s", rec.Body)
		}
		if cfg.JWKSURI != "" {
			t.Errorf("jwks_uri %q comes from the config file, want it ignored", cfg.JWKSURI)
		}
	}
	if got, want := strings.Join(p.seen(), ", "), "/token client:"+lockedSecret; got != want {
		t.Errorf("provider got %q, want %q", got, want)
	}
}

func TestLockedConfigIsFixed(t *testing.T) {
	p := newProvider(t)
	s := newLockedServer(t, p)
	fixed := s.config.Get()
	file, err := os.ReadFile(s.config.filepath)
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := &browser{t: t, s: s}, &browser{t: t, s: s}

	for _, tc := range []struct{ name, body, field string }{
		{"another token_url", `{"token_url":"https://evil.example/token"}`, "token_url"},
		{"another userinfo_url", `{"userinfo_url":"https://evil.example/userinfo"}`, "userinfo_url"},
		{"another client", `{"client_id":"other"}`, "client_id"},
		{"another redirect URI", `{"redirect_uri":"https://evil.example/cb"}`, "redirect_uri"},
		{"a secret", `{"client_secret":"guess"}`, "client_secret"},
		{"the right secret", `{"client_secret":"` + lockedSecret + `"}`, "client_secret"},
		{"settings along with another token_url", `{"scopes":["openid"],"token_url":"https://evil.example/token"}`, "token_url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out map[string]string
			alice.json(http.MethodPost, "/api/config", tc.body, http.StatusForbidden, &out)
			if !strings.Contains(out["error"], tc.field) {
				t.Errorf("error %q, want it to name %s", out["error"], tc.field)
			}
			var cfg configView
			alice.json(http.MethodGet, "/api/config", "", 200, &cfg)
			if cfg.TokenURL != fixed.TokenURL || cfg.ClientID != fixed.ClientID || strings.Join(cfg.Scopes, " ") != "openid profile email" {
				t.Errorf("config changed: %+v", cfg)
			}
		})
	}

	// The settings a tester tunes are saved, for their session only, even
	// sent with the fixed fields as the form has them.
	var saved configView
	alice.json(http.MethodPost, "/api/config", `{"token_url":"`+fixed.TokenURL+`","client_id":"client",
		"scopes":["openid","offline"],"response_type":"code id_token","response_mode":"fragment",
		"pkce_enabled":true,"pkce_method":"plain",
		"extra_authorize_params":{"prompt":"login"},"extra_token_params":{"resource":"api"}}`, 200, &saved)
	var got, other configView
	alice.json(http.MethodGet, "/api/config", "", 200, &got)
	bob.json(http.MethodGet, "/api/config", "", 200, &other)
	for name, cfg := range map[string]configView{"answer to the save": saved, "alice's config": got} {
		if strings.Join(cfg.Scopes, " ") != "openid offline" || cfg.ResponseType != "code id_token" || cfg.ResponseMode != "fragment" ||
			!cfg.PKCEEnabled || cfg.PKCEMethod != "plain" || cfg.ExtraAuthorizeParams["prompt"] != "login" || cfg.ExtraTokenParams["resource"] != "api" {
			t.Errorf("%s: %+v, want the settings saved", name, cfg)
		}
		if cfg.TokenURL != fixed.TokenURL || cfg.ClientSecret != "" {
			t.Errorf("%s: %+v, want the fixed provider and no secret", name, cfg)
		}
	}
	if strings.Join(other.Scopes, " ") != "openid profile email" || other.PKCEEnabled || len(other.ExtraAuthorizeParams) != 0 {
		t.Errorf("bob's config %+v, want the defaults", other)
	}

	// Alice's flows use her settings, bob's the defaults.
	loc := func(b *browser) url.Values {
		rec := b.do(http.MethodGet, "/auth/start", "")
		u, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query()
	}
	if q := loc(alice); q.Get("scope") != "openid offline" || q.Get("prompt") != "login" || q.Get("code_challenge_method") != "plain" || q.Get("client_id") != "client" {
		t.Errorf("alice's authorization request %v, want her settings", q)
	}
	if q := loc(bob); q.Get("scope") != "openid profile email" || q.Has("prompt") || q.Has("code_challenge") {
		t.Errorf("bob's authorization request %v, want the defaults", q)
	}

	if now := s.config.Get(); now.TokenURL != fixed.TokenURL || now.ClientSecret != lockedSecret || len(now.Scopes) != 3 {
		t.Errorf("shared config changed: %+v", now)
	}
	if after, _ := os.ReadFile(s.config.filepath); string(after) != string(file) {
		t.Errorf("config file rewritten: %s", after)
	}
}

func TestLockedIgnoresURLsAndCredentialsOfTheBody(t *testing.T) {
	p := newProvider(t)
	evil := newProvider(t)
	s := newLockedServer(t, p)
	fixed := s.config.Get()

	creds := `"client_id":"other","client_secret":"other-secret"`
	for _, tc := range []struct{ name, path, body, hit string }{
		{"userinfo", "/api/userinfo", `{"userinfo_url":"` + evil.URL + `/userinfo","access_token":"at"}`, "/userinfo :"},
		{"introspect", "/api/introspect", `{"introspection_url":"` + evil.URL + `/introspect","token":"at",` + creds + `}`, "/introspect client:" + lockedSecret},
		{"token exchange", "/api/token/exchange", `{"token_url":"` + evil.URL + `/token","code":"c","redirect_uri":"` + evil.URL + `/cb",` + creds + `}`, "/token client:" + lockedSecret},
		{"token refresh", "/api/token/refresh", `{"token_url":"` + evil.URL + `/token","refresh_token":"rt",` + creds + `}`, "/token client:" + lockedSecret},
		{"discovery", "/api/discover", `{"issuer_url":"` + evil.URL + `","update_config":true}`, "/.well-known/openid-configuration :"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(p.seen())
			b := &browser{t: t, s: s}
			var res OIDCResult
			b.json(http.MethodPost, tc.path, tc.body, 200, &res)
			if !strings.HasPrefix(res.Request.URL, p.URL) {
				t.Errorf("request sent to %s, want the provider %s", res.Request.URL, p.URL)
			}
			if strings.Contains(res.Request.Body, evil.URL) {
				t.Errorf("request body %q carries the redirect URI of the body", res.Request.Body)
			}
			if hits := p.seen()[before:]; len(hits) != 1 || hits[0] != tc.hit {
				t.Errorf("provider got %q, want %q", hits, tc.hit)
			}
		})
	}
	if hits := evil.seen(); len(hits) != 0 {
		t.Errorf("the URLs of the bodies were called: %q", hits)
	}
	// Discovery found another token endpoint, and update_config asked for it.
	if now := s.config.Get(); now.TokenURL != fixed.TokenURL {
		t.Errorf("discovery changed token_url to %s", now.TokenURL)
	}

	t.Run("authorize URL", func(t *testing.T) {
		b := &browser{t: t, s: s}
		var out struct {
			URL string `json:"url"`
		}
		b.json(http.MethodPost, "/api/authorize-url",
			`{"authorization_url":"https://evil.example/auth","client_id":"other","redirect_uri":"https://evil.example/cb","scopes":["openid"]}`, 200, &out)
		u, err := url.Parse(out.URL)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if !strings.HasPrefix(out.URL, fixed.AuthorizationURL+"?") || q.Get("client_id") != "client" || q.Get("redirect_uri") != fixed.RedirectURI {
			t.Errorf("URL %s, want the fixed endpoint, client and redirect URI", out.URL)
		}
		if q.Get("scope") != "openid" {
			t.Errorf("scope %q, want the one of the body", q.Get("scope"))
		}
	})
}

func TestLockedCallbackOfAnotherSession(t *testing.T) {
	p := newProvider(t)
	s := newLockedServer(t, p)
	alice, bob := &browser{t: t, s: s}, &browser{t: t, s: s}
	state := alice.start()
	bob.start()
	target := "/auth/callback?code=stolen&state=" + url.QueryEscape(state)

	for name, b := range map[string]*browser{"another session": bob, "no session": {t: t, s: s}} {
		rec := b.do(http.MethodGet, target, "")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid or expired state") {
			t.Errorf("%s: status %d, want the state refused: %s", name, rec.Code, rec.Body)
		}
	}
	if hits := p.seen(); len(hits) != 0 {
		t.Errorf("the code was exchanged: %q", hits)
	}
	if h := bob.history(); len(h) != 0 {
		t.Errorf("bob's history %+v, want it empty", h)
	}

	// The state is still alice's to use, once.
	if rec := alice.do(http.MethodGet, target, ""); rec.Code != http.StatusFound {
		t.Fatalf("alice's callback: status %d: %s", rec.Code, rec.Body)
	}
	if rec := alice.do(http.MethodGet, target, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("the state served twice: status %d", rec.Code)
	}

	// The states of the Authorize tab are the session's too.
	var out struct {
		State string `json:"state"`
	}
	alice.json(http.MethodPost, "/api/authorize-url", `{}`, 200, &out)
	if rec := bob.do(http.MethodGet, "/auth/callback?code=c&state="+url.QueryEscape(out.State), ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bob's callback with a state of alice's Authorize tab: status %d", rec.Code)
	}
}

func TestLockedLogoutUsesTheSessionsFlows(t *testing.T) {
	p := newProvider(t)
	s := newLockedServer(t, p)
	alice, bob := &browser{t: t, s: s}, &browser{t: t, s: s}
	id := alice.flow("alice")

	for body, errText := range map[string]string{
		"":           "no id_token in the history",
		"flow=" + id: "is not in the history",
	} {
		rec := bob.do(http.MethodPost, "/auth/logout", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errText) {
			t.Errorf("bob's logout %q: status %d, want %q: %s", body, rec.Code, errText, rec.Body)
		}
	}
	if h := alice.history(); h[0].LoggedOutAt != nil {
		t.Errorf("bob's logout marked alice's flow")
	}

	bob.flow("bob")
	for b, hint := range map[*browser]string{alice: "id-alice", bob: "id-bob"} {
		rec := b.do(http.MethodPost, "/auth/logout", "")
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusFound || loc.Query().Get("id_token_hint") != hint {
			t.Errorf("logout: status %d, to %s, want the id_token_hint %s", rec.Code, loc, hint)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	static := fstest.MapFS{"static/index.html": {Data: []byte("<html></html>")}}
	for _, locked := range []bool{true, false} {
		s := New(Options{StaticFS: static, ConfigFile: filepath.Join(t.TempDir(), "config.json"), Locked: locked})
		for _, path := range []string{"/", "/api/config", "/api/history", "/auth/start", "/auth/callback?state=x"} {
			rec := (&browser{t: t, s: s}).do(http.MethodGet, path, "")
			h := rec.Header()
			wantCSP, wantRef, wantCache := "", "", ""
			if locked {
				wantCSP, wantRef = "default-src 'self'; frame-ancestors 'none'", "no-referrer"
				if path != "/" {
					wantCache = "no-store"
				}
			}
			if h.Get("Content-Security-Policy") != wantCSP || h.Get("Referrer-Policy") != wantRef || h.Get("Cache-Control") != wantCache {
				t.Errorf("locked %v, %s: CSP %q, Referrer-Policy %q, Cache-Control %q, want %q, %q, %q", locked, path,
					h.Get("Content-Security-Policy"), h.Get("Referrer-Policy"), h.Get("Cache-Control"), wantCSP, wantRef, wantCache)
			}
		}
	}
}

func TestSessionTTL(t *testing.T) {
	p := newProvider(t)
	s := newLockedServer(t, p)
	alice, bob := &browser{t: t, s: s}, &browser{t: t, s: s}
	alice.flow("alice")
	bob.flow("bob")
	bob.start()

	// Alice was last seen a TTL ago; bob has a state left waiting too long.
	s.sessionsMu.Lock()
	s.sessions[alice.cookie.Value].seen = time.Now().Add(-s.sessionTTL)
	bobs := s.sessions[bob.cookie.Value]
	s.sessionsMu.Unlock()
	bobs.mu.Lock()
	for _, st := range bobs.states {
		st.CreatedAt = time.Now().Add(-flowStateTTL - time.Second)
	}
	bobs.mu.Unlock()

	// Her history is gone before the cleaning, and from the memory after.
	if h := alice.history(); len(h) != 0 {
		t.Errorf("alice's history %+v after the TTL, want it empty", h)
	}
	s.clean(time.Now())
	s.sessionsMu.Lock()
	_, kept := s.sessions[alice.cookie.Value]
	n := len(s.sessions)
	s.sessionsMu.Unlock()
	if kept || n != 1 {
		t.Errorf("after the cleaning, alice's session kept: %v, %d sessions, want bob's only", kept, n)
	}
	if h := bob.history(); len(h) != 1 {
		t.Errorf("bob's history %+v, want his flow kept", h)
	}
	bobs.mu.Lock()
	left := len(bobs.states)
	bobs.mu.Unlock()
	if left != 0 {
		t.Errorf("%d stale states left", left)
	}

	if s.sessionTTL != DefaultSessionTTL {
		t.Errorf("session TTL %v, want the default %v", s.sessionTTL, DefaultSessionTTL)
	}
}

// Not locked, the client is as before: one config and one history for
// everyone, the secret shown, the URLs of the bodies called, and no cookie.
func TestUnlockedIsUnchanged(t *testing.T) {
	p := newProvider(t)
	other := newProvider(t)
	s := newTestServer(t, Config{
		AuthorizationURL: p.URL + "/auth", TokenURL: p.URL + "/token", UserinfoURL: p.URL + "/userinfo",
		ClientID: "client", ClientSecret: lockedSecret, RedirectURI: "https://rp.example/auth/callback",
	})
	alice, bob := &browser{t: t, s: s}, &browser{t: t, s: s}

	state := alice.start()
	if rec := bob.do(http.MethodGet, "/auth/callback?code=c&state="+url.QueryEscape(state), ""); rec.Code != http.StatusFound {
		t.Fatalf("callback from another browser: status %d: %s", rec.Code, rec.Body)
	}
	if h := alice.history(); len(h) != 1 {
		t.Errorf("history %+v, want the flow, shared", h)
	}

	var cfg configView
	bob.json(http.MethodPost, "/api/config", `{"token_url":"`+other.URL+`/token","client_secret":"new"}`, 200, &cfg)
	alice.json(http.MethodGet, "/api/config", "", 200, &cfg)
	if cfg.Locked || cfg.TokenURL != other.URL+"/token" || cfg.ClientSecret != "new" {
		t.Errorf("config %+v, want bob's change, secret included", cfg)
	}

	alice.json(http.MethodPost, "/api/userinfo", `{"userinfo_url":"`+other.URL+`/userinfo","access_token":"at"}`, 200, nil)
	if hits := other.seen(); len(hits) != 1 || hits[0] != "/userinfo :" {
		t.Errorf("the userinfo_url of the body got %q, want the request", hits)
	}
	if alice.cookie != nil || bob.cookie != nil {
		t.Errorf("a session cookie was set: %v, %v", alice.cookie, bob.cookie)
	}
}

package app

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s := New(Options{StaticFS: fstest.MapFS{}, ConfigFile: filepath.Join(t.TempDir(), "config.json")})
	s.config.Set(cfg)
	return s
}

func tokenResult(body string) *OIDCResult {
	return &OIDCResult{Response: &ResponseLog{Status: 200, Body: body}}
}

func TestLogout(t *testing.T) {
	cfg := Config{
		ClientID:              "client",
		EndSessionURL:         "https://op.example/logout?ui=fr",
		PostLogoutRedirectURI: "https://rp.example/",
	}
	for _, tc := range []struct {
		name    string
		cfg     Config
		history []*OIDCResult
		query   string
		method  string
		header  map[string]string
		code    int
		hint    string
		back    bool
		errText string
	}{
		{name: "the newest flow with an id_token", cfg: cfg,
			history: []*OIDCResult{tokenResult(`{"id_token":"old"}`), tokenResult(`{"id_token":"new"}`), tokenResult(`{"access_token":"a"}`)},
			code:    http.StatusFound, hint: "new", back: true},
		{name: "the flow named", cfg: cfg,
			history: []*OIDCResult{tokenResult(`{"id_token":"old"}`), tokenResult(`{"id_token":"new"}`)},
			query:   "first", code: http.StatusFound, hint: "old", back: true},
		{name: "without a post logout redirect URI, neither it nor a state",
			cfg:     Config{EndSessionURL: cfg.EndSessionURL},
			history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			code:    http.StatusFound, hint: "new"},
		{name: "the flow named has no id_token", cfg: cfg,
			history: []*OIDCResult{tokenResult(`{"access_token":"a"}`), tokenResult(`{"id_token":"new"}`)},
			query:   "first", code: http.StatusBadRequest, errText: "has no id_token"},
		{name: "a flow unknown", cfg: cfg, history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			query: "gone", code: http.StatusBadRequest, errText: "is not in the history"},
		{name: "no history", cfg: cfg, code: http.StatusBadRequest, errText: "no id_token in the history"},
		{name: "a GET", cfg: cfg, history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			method: http.MethodGet, code: http.StatusMethodNotAllowed},
		{name: "from another site", cfg: cfg, history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			header: map[string]string{"Sec-Fetch-Site": "cross-site"}, code: http.StatusForbidden},
		{name: "from another origin, without Sec-Fetch-Site", cfg: cfg, history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			header: map[string]string{"Origin": "https://evil.example"}, code: http.StatusForbidden},
		{name: "from the client's own page", cfg: cfg, history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			header: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"},
			code:   http.StatusFound, hint: "new", back: true},
		{name: "no end session URL", cfg: Config{PostLogoutRedirectURI: "https://rp.example/"},
			history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)}, code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, tc.cfg)
			ids := map[string]string{}
			for i, res := range tc.history {
				id := s.addHistory(res, nil)
				if i == 0 {
					ids["first"] = id
				}
			}
			// The entry whose id_token went as the hint, the only one noted,
			// with the state sent.
			var sentState string
			defer func() {
				for _, e := range s.history {
					used := tc.code == http.StatusFound && idTokenOfResult(e.Result) == tc.hint
					if used != (e.LoggedOutAt != nil) {
						t.Errorf("entry %s: logged_out_at %v, want it: %v", idTokenOfResult(e.Result), e.LoggedOutAt, used)
					}
					if used && e.LogoutState != sentState {
						t.Errorf("entry %s: logout_state %q, want %q", idTokenOfResult(e.Result), e.LogoutState, sentState)
					}
				}
			}()
			form := url.Values{}
			if tc.query != "" {
				flow := ids[tc.query]
				if flow == "" {
					flow = tc.query
				}
				form.Set("flow", flow)
			}
			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/auth/logout", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.errText) {
				t.Errorf("body %q, want it to say %q", rec.Body, tc.errText)
			}
			if tc.code != http.StatusFound {
				return
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			q := loc.Query()
			sentState = q.Get("state")
			if loc.Scheme+"://"+loc.Host+loc.Path != "https://op.example/logout" || q.Get("ui") != "fr" {
				t.Errorf("location %s: the end session URL and its query kept", loc)
			}
			if q.Get("id_token_hint") != tc.hint {
				t.Errorf("id_token_hint %q, want %q", q.Get("id_token_hint"), tc.hint)
			}
			if got := q.Get("post_logout_redirect_uri"); tc.back != (got == "https://rp.example/") || tc.back != (q.Get("state") != "") {
				t.Errorf("post_logout_redirect_uri %q, state %q, want them: %v", got, q.Get("state"), tc.back)
			}
		})
	}
}

func TestRenderCallbackErrorEscapes(t *testing.T) {
	rec := httptest.NewRecorder()
	renderCallbackError(rec, `invalid end_session_url: parse "http://%zz<script>x</script>"`)
	if body := rec.Body.String(); strings.Contains(body, "<script>") {
		t.Errorf("message not escaped: %s", body)
	}
}

func TestHistoryIDTokenClaims(t *testing.T) {
	s := newTestServer(t, Config{})
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice","exp":1}`))
	s.addHistory(tokenResult(`{"id_token":"e30.`+payload+`.sig"}`), nil)
	s.addHistory(tokenResult(`{"access_token":"a"}`), nil)
	if got := s.history[0].IDTokenClaims["sub"]; got != "alice" {
		t.Errorf("claims sub %v, want alice", got)
	}
	if got := s.history[1].IDTokenClaims; got != nil {
		t.Errorf("claims %v without an id_token, want none", got)
	}
}

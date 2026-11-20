package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
		code    int
		hint    string
		back    bool
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
			query:   "first", code: http.StatusBadRequest},
		{name: "a flow unknown", cfg: cfg, history: []*OIDCResult{tokenResult(`{"id_token":"new"}`)},
			query: "gone", code: http.StatusBadRequest},
		{name: "no history", cfg: cfg, code: http.StatusBadRequest},
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
			target := "/auth/logout"
			if tc.query != "" {
				flow := ids[tc.query]
				if flow == "" {
					flow = tc.query
				}
				target += "?flow=" + url.QueryEscape(flow)
			}
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body)
			}
			if tc.code != http.StatusFound {
				return
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			q := loc.Query()
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

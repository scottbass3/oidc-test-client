package app

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const testWebURL = "https://example.com/auth/client/"

// newPrefixedServer returns a locked server served at webURL, whose redirect
// URIs are left to default.
func newPrefixedServer(t *testing.T, p *provider, webURL string) *Server {
	t.Helper()
	newLockedServer(t, p) // sets the environment
	t.Setenv("OIDC_REDIRECT_URI", "")
	static := fstest.MapFS{
		"static/index.html": {Data: []byte("<html>index</html>")},
		"static/style.css":  {Data: []byte("body{}")},
	}
	return New(Options{StaticFS: static, ConfigFile: filepath.Join(t.TempDir(), "config.json"), Locked: true, WebURL: webURL})
}

// The proxy in front either forwards the path under the prefix as it is, or
// strips the prefix: both have to work, from the page to the logout.
func TestPrefix(t *testing.T) {
	for name, base := range map[string]string{"prefix forwarded": "/auth/client", "prefix stripped": ""} {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t)
			b := &browser{t: t, s: newPrefixedServer(t, p, testWebURL)}

			for _, static := range []string{"/", "/style.css"} {
				if rec := b.do(http.MethodGet, base+static, ""); rec.Code != 200 {
					t.Errorf("GET %s: status %d", base+static, rec.Code)
				}
			}

			var cfg Config
			b.json(http.MethodGet, base+"/api/config", "", 200, &cfg)
			if cfg.RedirectURI != testWebURL+"auth/callback" {
				t.Errorf("redirect_uri = %q", cfg.RedirectURI)
			}
			if cfg.PostLogoutRedirectURI != testWebURL {
				t.Errorf("post_logout_redirect_uri = %q", cfg.PostLogoutRedirectURI)
			}
			if b.cookie == nil || b.cookie.Name != prefixedSessionCookie || b.cookie.Path != "/auth/client/" {
				t.Fatalf("session cookie = %+v", b.cookie)
			}

			b.json(http.MethodPost, base+"/api/discover", `{}`, 200, nil)

			// The full flow.
			rec := b.do(http.MethodGet, base+"/auth/start", "")
			if rec.Code != http.StatusFound {
				t.Fatalf("/auth/start: status %d: %s", rec.Code, rec.Body)
			}
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if got := loc.Query().Get("redirect_uri"); got != testWebURL+"auth/callback" {
				t.Errorf("redirect_uri sent = %q", got)
			}
			rec = b.do(http.MethodGet, base+"/auth/callback?code=c1&state="+url.QueryEscape(loc.Query().Get("state")), "")
			if rec.Code != http.StatusFound {
				t.Fatalf("/auth/callback: status %d: %s", rec.Code, rec.Body)
			}
			flow, ok := strings.CutPrefix(rec.Header().Get("Location"), "/auth/client/?flow=")
			if !ok {
				t.Fatalf("callback redirects to %q", rec.Header().Get("Location"))
			}

			var entry HistoryEntry
			b.json(http.MethodGet, base+"/api/history?id="+flow, "", 200, &entry)

			b.json(http.MethodPost, base+"/api/token/refresh", `{"refresh_token":"rt"}`, 200, nil)
			b.json(http.MethodPost, base+"/api/userinfo", `{"access_token":"at"}`, 200, nil)
			b.json(http.MethodPost, base+"/api/introspect", `{"token":"at"}`, 200, nil)

			rec = b.do(http.MethodPost, base+"/auth/logout", "flow="+flow)
			if rec.Code != http.StatusFound {
				t.Fatalf("/auth/logout: status %d: %s", rec.Code, rec.Body)
			}
			loc, _ = url.Parse(rec.Header().Get("Location"))
			if got := loc.Query().Get("post_logout_redirect_uri"); got != testWebURL {
				t.Errorf("post_logout_redirect_uri sent = %q", got)
			}

			want := []string{"/.well-known/openid-configuration", "/token", "/token", "/userinfo", "/introspect"}
			seen := p.seen()
			if len(seen) != len(want) {
				t.Fatalf("provider saw %v, want %v", seen, want)
			}
			for i, w := range want {
				if !strings.HasPrefix(seen[i], w+" ") {
					t.Errorf("provider saw %v, want %v", seen, want)
					break
				}
			}

			// The error page links under the prefix too.
			rec = b.do(http.MethodGet, base+"/auth/callback?state=unknown", "")
			body := rec.Body.String()
			if !strings.Contains(body, `href="/auth/client/style.css"`) || !strings.Contains(body, `<a href="/auth/client/">`) {
				t.Errorf("error page: %s", body)
			}
		})
	}
}

func TestPrefixWithoutTrailingSlashRedirects(t *testing.T) {
	b := &browser{t: t, s: newPrefixedServer(t, newProvider(t), testWebURL)}
	rec := b.do(http.MethodGet, "/auth/client?flow=abc", "")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/auth/client/?flow=abc" {
		t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// Under a prefix that is also the start of a route, a stripped path looks like
// one under the prefix: /auth/start is /auth/ + start, or the stripped
// /auth/auth/start.
func TestPrefixThatLooksLikeARoute(t *testing.T) {
	b := &browser{t: t, s: newPrefixedServer(t, newProvider(t), "https://example.com/auth/")}
	for _, target := range []string{"/auth/auth/start", "/auth/start"} {
		if rec := b.do(http.MethodGet, target, ""); rec.Code != http.StatusFound {
			t.Errorf("GET %s: status %d", target, rec.Code)
		}
	}
	for _, target := range []string{"/auth/style.css", "/style.css", "/auth/"} {
		if rec := b.do(http.MethodGet, target, ""); rec.Code != 200 {
			t.Errorf("GET %s: status %d", target, rec.Code)
		}
	}
}

// A WEB_URL without a path only sets the default redirect URIs, and the
// environment still wins over them.
func TestWebURLAtTheRoot(t *testing.T) {
	p := newProvider(t)
	newLockedServer(t, p)
	t.Setenv("OIDC_POST_LOGOUT_REDIRECT_URI", "")
	s := New(Options{StaticFS: fstest.MapFS{}, ConfigFile: filepath.Join(t.TempDir(), "config.json"), Locked: true, WebURL: "https://rp.example/"})
	b := &browser{t: t, s: s}

	var cfg Config
	b.json(http.MethodGet, "/api/config", "", 200, &cfg)
	if cfg.RedirectURI != "https://rp.example/auth/callback" || cfg.PostLogoutRedirectURI != "https://rp.example/" {
		t.Errorf("redirect_uri = %q, post_logout_redirect_uri = %q", cfg.RedirectURI, cfg.PostLogoutRedirectURI)
	}
	if b.cookie == nil || b.cookie.Name != sessionCookie || b.cookie.Path != "/" {
		t.Errorf("session cookie = %+v", b.cookie)
	}
	if loc := b.do(http.MethodGet, "/auth/callback?code=c&state="+url.QueryEscape(b.start()), "").Header().Get("Location"); !strings.HasPrefix(loc, "/?flow=") {
		t.Errorf("callback redirects to %q", loc)
	}
}

func TestParseWebURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com":              "https://example.com/",
		"https://example.com/":             "https://example.com/",
		"https://example.com/auth/client":  "https://example.com/auth/client/",
		"https://example.com/auth/client/": "https://example.com/auth/client/",
		"http://localhost:8080/a//b/":      "http://localhost:8080/a/b/",
	} {
		if got, err := ParseWebURL(in); err != nil || got != want {
			t.Errorf("ParseWebURL(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"example.com/auth", "/auth/client/", "ftp://example.com/", "https://example.com/?a=b", "https://example.com/#top", "https://u:p@example.com/"} {
		if got, err := ParseWebURL(in); err == nil {
			t.Errorf("ParseWebURL(%q) = %q, want an error", in, got)
		}
	}
}

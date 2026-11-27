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
		"static/index.html": {Data: []byte("<html><head></head>index</html>")},
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
			if body := b.do(http.MethodGet, base+"/", "").Body.String(); !strings.Contains(body, `<head>`+"\n"+`  <base href="/auth/client/">`) {
				t.Errorf("page without the <base> of the prefix: %s", body)
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
	for _, in := range []string{"example.com/auth", "/auth/client/", "ftp://example.com/", "https://example.com/?a=b", "https://example.com/#top", "https://u:p@example.com/",
		"https://example.com/a%3Fb/", "https://example.com/a b/"} {
		if got, err := ParseWebURL(in); err == nil {
			t.Errorf("ParseWebURL(%q) = %q, want an error", in, got)
		}
	}
}

// New takes a WebURL as it is typed, and refuses one ParseWebURL refuses.
func TestNewNormalizesWebURL(t *testing.T) {
	s := New(Options{StaticFS: fstest.MapFS{}, ConfigFile: filepath.Join(t.TempDir(), "config.json"), WebURL: "https://example.com/auth/client"})
	if s.basePath != "/auth/client/" || s.config.Get().RedirectURI != testWebURL+"auth/callback" {
		t.Errorf("basePath = %q, redirect_uri = %q", s.basePath, s.config.Get().RedirectURI)
	}
	defer func() {
		if recover() == nil {
			t.Error("New accepted a WebURL without a scheme")
		}
	}()
	New(Options{StaticFS: fstest.MapFS{}, WebURL: "example.com/auth"})
}

// The defaults under WEB_URL are not saved with the configuration: they
// follow WEB_URL when it changes, and a redirect URI of the tester's is kept.
func TestWebURLDefaultsAreNotSaved(t *testing.T) {
	for _, k := range []string{"OIDC_REDIRECT_URI", "OIDC_POST_LOGOUT_REDIRECT_URI"} {
		t.Setenv(k, "")
	}
	file := filepath.Join(t.TempDir(), "config.json")
	open := func(webURL string) *Server {
		return New(Options{StaticFS: fstest.MapFS{}, ConfigFile: file, WebURL: webURL})
	}

	// The page posts back the configuration it was given, defaults included.
	s := open("https://a.example/app/")
	cfg := s.config.Get()
	cfg.ClientID = "client"
	s.config.Set(cfg)

	cfg = open("https://b.example/").config.Get()
	if cfg.ClientID != "client" || cfg.RedirectURI != "https://b.example/auth/callback" || cfg.PostLogoutRedirectURI != "https://b.example/" {
		t.Errorf("after a change of WEB_URL: %+v", cfg)
	}

	cfg.RedirectURI = "https://other.example/cb"
	s = open("https://b.example/")
	s.config.Set(cfg)
	if got := open("https://c.example/").config.Get().RedirectURI; got != "https://other.example/cb" {
		t.Errorf("redirect_uri of the tester = %q", got)
	}
}

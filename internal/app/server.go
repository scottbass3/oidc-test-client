package app

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	maxHistory = 10

	// flowStateTTL is how long a pending state waits for its callback.
	flowStateTTL = 10 * time.Minute

	// DefaultSessionTTL is how long a locked mode session outlives its last
	// request.
	DefaultSessionTTL = 12 * time.Hour

	// What anyone who reaches a locked instance can have it keep is bounded:
	// maxSessions sessions, a new one taking the place of the one that loses
	// least past that, maxStates pending states in each, and requests whose
	// body, the settings a session keeps included, is at most maxLockedBody
	// bytes.
	maxSessions   = 1000
	maxStates     = 20
	maxLockedBody = 64 << 10

	// sessionCookie names the cookie of a locked mode session. The __Host-
	// prefix has browsers refuse it unless it is Secure and bound to this host.
	sessionCookie = "__Host-oidc-test-client"

	// prefixedSessionCookie names it when the client is served under a path
	// prefix: __Host- wants the path "/", so the cookie, bound to the prefix,
	// only keeps the Secure half of the guarantee.
	prefixedSessionCookie = "__Secure-oidc-test-client"
)

type FlowState struct {
	State         string
	Nonce         string
	CodeVerifier  string
	CodeChallenge string
	CreatedAt     time.Time
}

type HistoryEntry struct {
	ID             string            `json:"id"`
	CreatedAt      time.Time         `json:"created_at"`
	Result         *OIDCResult       `json:"result"`
	CallbackParams map[string]string `json:"callback_params,omitempty"`
	// IDTokenClaims is the unverified payload of the flow's id_token.
	IDTokenClaims map[string]interface{} `json:"id_token_claims,omitempty"`
	// LoggedOutAt is when a logout was sent with this flow's id_token, and
	// LogoutState the state sent with it, to check the one coming back.
	LoggedOutAt *time.Time `json:"logged_out_at,omitempty"`
	LogoutState string     `json:"logout_state,omitempty"`

	// signedIn is whether the provider issued a token for the flow, which takes
	// a real sign-in, unlike a failed exchange that anyone can have recorded.
	signedIn bool
}

// session is what the client keeps for one browser: the states waiting for
// their callback, the history of the flows and, in locked mode, the settings
// the tester tuned.
type session struct {
	mu       sync.Mutex
	states   map[string]*FlowState
	history  []*HistoryEntry
	settings *Config // nil until the tester saves some

	seen time.Time // last request, guarded by Server.sessionsMu
}

func newSession() *session {
	return &session{states: make(map[string]*FlowState)}
}

type Server struct {
	mux      *http.ServeMux
	routes   map[string]bool // the paths registered on mux, the static files aside
	config   *ConfigStore
	staticFS fs.FS

	// basePath is the path the client is served under, "/" unless WebURL has
	// one. It starts and ends with "/".
	basePath   string
	cookieName string

	// locked is the mode for shared deployments: the provider and the client
	// are fixed by the environment, and each browser has its own session.
	locked     bool
	sessionTTL time.Duration

	// shared is the one session of everyone when not locked.
	shared *session

	sessionsMu sync.Mutex
	sessions   map[string]*session // locked mode, by cookie value
}

type Options struct {
	StaticFS   fs.FS
	ConfigFile string
	// Locked turns on the mode for shared deployments.
	Locked bool
	// SessionTTL is how long a locked mode session outlives its last request,
	// DefaultSessionTTL when zero.
	SessionTTL time.Duration
	// WebURL is the public URL of the client, as ParseWebURL returns it, when
	// it is served under a path of its host or to have the redirect URIs
	// default to it. Empty, the client is at the root of its host.
	WebURL string
}

// ParseWebURL checks v, the public URL of the client, and returns it with a
// path that ends with "/".
func ParseWebURL(v string) (string, error) {
	u, err := url.Parse(v)
	if err != nil {
		return "", err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("want an absolute http or https URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("want no query, fragment or credentials")
	}
	u.Path, u.RawPath = path.Clean("/"+u.Path), ""
	if u.Path != "/" {
		u.Path += "/"
	}
	return u.String(), nil
}

func New(opts Options) *Server {
	ttl := opts.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	basePath, cookieName := "/", sessionCookie
	if u, err := url.Parse(opts.WebURL); err == nil && strings.HasSuffix(u.Path, "/") && u.Path != "/" {
		basePath, cookieName = u.Path, prefixedSessionCookie
	}
	s := &Server{
		mux:        http.NewServeMux(),
		routes:     make(map[string]bool),
		config:     NewConfigStore(opts.ConfigFile, opts.Locked, opts.WebURL),
		staticFS:   opts.StaticFS,
		basePath:   basePath,
		cookieName: cookieName,
		locked:     opts.Locked,
		sessionTTL: ttl,
		shared:     newSession(),
		sessions:   make(map[string]*session),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Start(addr string) error {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for now := range ticker.C {
			s.clean(now)
		}
	}()
	return http.ListenAndServe(addr, s)
}

// ServeHTTP serves the client, in locked mode with the security headers.
//
// Locked, a POST to the API has to come from the client's own page, as JSON:
// a form on another site can send neither, and so cannot change a tester's
// session, or give them a new one, behind their back.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.basePath != "/" {
		// The page calls the server with relative URLs, which only resolve
		// under the prefix when its own URL ends with "/".
		if r.URL.Path+"/" == s.basePath {
			target := s.basePath
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		r = s.stripBasePath(r)
	}
	if s.locked {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		// same-origin, not no-referrer, which would have the page's own form
		// POST, the logout, sent with "Origin: null" and so taken for
		// cross-origin where Sec-Fetch-Site is missing. The provider gets no
		// referrer either way.
		h.Set("Referrer-Policy", "same-origin")
		api := strings.HasPrefix(r.URL.Path, "/api/")
		if api || strings.HasPrefix(r.URL.Path, "/auth/") {
			h.Set("Cache-Control", "no-store")
		}
		if api && r.Method == http.MethodPost {
			if !sameOrigin(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
				return
			}
			if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxLockedBody)
	}
	s.mux.ServeHTTP(w, r)
}

// stripBasePath returns r with the path the routes know: the reverse proxy in
// front may forward the path under the prefix as it is, or strip the prefix
// itself. A path that is a route as it comes, and none without the prefix, was
// stripped already: under the prefix /auth/, /auth/start is the stripped
// /auth/auth/start.
func (s *Server) stripBasePath(r *http.Request) *http.Request {
	p := r.URL.Path
	if !strings.HasPrefix(p, s.basePath) {
		return r
	}
	stripped := "/" + p[len(s.basePath):]
	if s.routes[p] && !s.routes[stripped] {
		return r
	}
	r2 := new(http.Request)
	*r2 = *r
	r2.URL = new(url.URL)
	*r2.URL = *r.URL
	r2.URL.Path = stripped
	r2.URL.RawPath = ""
	return r2
}

// session returns the session of the browser behind r. Not locked, it is the
// one everyone shares. Locked, it is the one its cookie names; a browser
// without one gets an empty session that is not kept, so that reading costs
// the server nothing.
func (s *Server) session(r *http.Request) *session {
	if !s.locked {
		return s.shared
	}
	if sess := s.cookieSession(r); sess != nil {
		return sess
	}
	return newSession()
}

// openSession is session for the requests that store something: locked, a
// browser without a session gets one, and the cookie that names it. With
// maxSessions live already, it takes the place of another: filling the
// sessions keeps no one out.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request) (*session, error) {
	if !s.locked {
		return s.shared, nil
	}
	if sess := s.cookieSession(r); sess != nil {
		return sess, nil
	}
	id, err := generateRandom(32)
	if err != nil {
		return nil, err
	}
	sess := newSession()
	sess.seen = time.Now()
	s.sessionsMu.Lock()
	if len(s.sessions) >= maxSessions {
		s.dropExpired(sess.seen)
	}
	if len(s.sessions) >= maxSessions {
		s.evict()
	}
	s.sessions[id] = sess
	s.sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    id,
		Path:     s.basePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return sess, nil
}

// cookieSession returns the live session the cookie of r names, nil without.
func (s *Server) cookieSession(r *http.Request) *session {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil
	}
	now := time.Now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || now.Sub(sess.seen) >= s.sessionTTL {
		return nil
	}
	sess.seen = now
	return sess
}

// clean drops the sessions not seen for the TTL, with their history, and the
// states still waiting for a callback after flowStateTTL.
func (s *Server) clean(now time.Time) {
	live := []*session{s.shared}
	s.sessionsMu.Lock()
	s.dropExpired(now)
	for _, sess := range s.sessions {
		live = append(live, sess)
	}
	s.sessionsMu.Unlock()

	for _, sess := range live {
		sess.mu.Lock()
		for k, v := range sess.states {
			if now.Sub(v.CreatedAt) > flowStateTTL {
				delete(sess.states, k)
			}
		}
		sess.mu.Unlock()
	}
}

// dropExpired drops the sessions not seen for the TTL. The caller holds
// sessionsMu.
func (s *Server) dropExpired(now time.Time) {
	for id, sess := range s.sessions {
		if now.Sub(sess.seen) >= s.sessionTTL {
			delete(s.sessions, id)
		}
	}
}

// evict drops the session that loses least: one that keeps nothing, as a
// request without a cookie opens, before one with settings, pending states or
// only failed flows, before one with a flow that signed in, and among those
// the one seen longest ago. The caller holds sessionsMu.
func (s *Server) evict() {
	var victim string
	var worth int
	var seen time.Time
	for id, sess := range s.sessions {
		w := sess.worth()
		if victim == "" || w < worth || (w == worth && sess.seen.Before(seen)) {
			victim, worth, seen = id, w, sess.seen
		}
	}
	delete(s.sessions, victim)
}

// worth ranks what a session would lose if dropped: 0 nothing, 1 settings,
// pending states or a history of failed flows, 2 a flow that signed in.
func (sess *session) worth() int {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	for _, e := range sess.history {
		if e.signedIn {
			return 2
		}
	}
	if len(sess.history) > 0 || sess.settings != nil || len(sess.states) > 0 {
		return 1
	}
	return 0
}

// configFor returns the configuration for a session: locked, the fixed one
// with the settings the tester tuned.
func (s *Server) configFor(sess *session) Config {
	cfg := s.config.Get()
	if !s.locked {
		return cfg
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.settings != nil {
		cfg.setTunables(*sess.settings)
	}
	return cfg
}

// addState keeps a pending state, in place of the oldest one when maxStates
// are waiting already.
func (sess *session) addState(fs *FlowState) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if _, known := sess.states[fs.State]; !known && len(sess.states) >= maxStates {
		var oldest *FlowState
		for _, st := range sess.states {
			if oldest == nil || st.CreatedAt.Before(oldest.CreatedAt) {
				oldest = st
			}
		}
		delete(sess.states, oldest.State)
	}
	sess.states[fs.State] = fs
}

// takeState returns the pending state and forgets it, as it serves once.
func (sess *session) takeState(state string) (*FlowState, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	fs, ok := sess.states[state]
	delete(sess.states, state)
	return fs, ok
}

func (sess *session) addHistory(result *OIDCResult, callbackParams map[string]string) string {
	id, _ := generateRandom(8)
	entry := &HistoryEntry{
		ID:             id,
		CreatedAt:      time.Now(),
		Result:         result,
		CallbackParams: callbackParams,
		IDTokenClaims:  idTokenClaims(idTokenOfResult(result)),
		signedIn:       tokensIssued(result),
	}
	sess.mu.Lock()
	sess.history = append(sess.history, entry)
	if len(sess.history) > maxHistory {
		sess.history = sess.history[len(sess.history)-maxHistory:]
	}
	sess.mu.Unlock()
	return id
}

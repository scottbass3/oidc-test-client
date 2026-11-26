package app

import (
	"io/fs"
	"net/http"
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

	// sessionCookie names the cookie of a locked mode session. The __Host-
	// prefix has browsers refuse it unless it is Secure and bound to this host.
	sessionCookie = "__Host-oidc-test-client"
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
	config   *ConfigStore
	staticFS fs.FS

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
}

func New(opts Options) *Server {
	ttl := opts.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	s := &Server{
		mux:        http.NewServeMux(),
		config:     NewConfigStore(opts.ConfigFile, opts.Locked),
		staticFS:   opts.StaticFS,
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
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.locked {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			h.Set("Cache-Control", "no-store")
		}
	}
	s.mux.ServeHTTP(w, r)
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
// browser without a session gets one, and the cookie that names it.
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
	s.sessions[id] = sess
	s.sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return sess, nil
}

// cookieSession returns the live session the cookie of r names, nil without.
func (s *Server) cookieSession(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
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
	for id, sess := range s.sessions {
		if now.Sub(sess.seen) >= s.sessionTTL {
			delete(s.sessions, id)
			continue
		}
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

func (sess *session) addState(fs *FlowState) {
	sess.mu.Lock()
	sess.states[fs.State] = fs
	sess.mu.Unlock()
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
	}
	sess.mu.Lock()
	sess.history = append(sess.history, entry)
	if len(sess.history) > maxHistory {
		sess.history = sess.history[len(sess.history)-maxHistory:]
	}
	sess.mu.Unlock()
	return id
}

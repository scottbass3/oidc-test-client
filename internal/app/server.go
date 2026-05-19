package app

import (
	"io/fs"
	"net/http"
	"sync"
	"time"
)

type FlowState struct {
	State         string
	Nonce         string
	CodeVerifier  string
	CodeChallenge string
	CreatedAt     time.Time
}

type Server struct {
	mux        *http.ServeMux
	config     *ConfigStore
	flowStates map[string]*FlowState
	flowMu     sync.Mutex
	staticFS   fs.FS
}

type Options struct {
	StaticFS   fs.FS
	ConfigFile string
}

func New(opts Options) *Server {
	s := &Server{
		mux:        http.NewServeMux(),
		config:     NewConfigStore(opts.ConfigFile),
		flowStates: make(map[string]*FlowState),
		staticFS:   opts.StaticFS,
	}
	s.registerRoutes()
	go s.cleanFlowStates()
	return s
}

func (s *Server) Start(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

// cleanFlowStates removes stale flow states older than 10 minutes.
func (s *Server) cleanFlowStates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.flowMu.Lock()
		for k, v := range s.flowStates {
			if time.Since(v.CreatedAt) > 10*time.Minute {
				delete(s.flowStates, k)
			}
		}
		s.flowMu.Unlock()
	}
}

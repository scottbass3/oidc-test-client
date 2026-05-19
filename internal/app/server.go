package app

import (
	"io/fs"
	"net/http"
	"sync"
	"time"
)

const maxHistory = 10

type FlowState struct {
	State         string
	Nonce         string
	CodeVerifier  string
	CodeChallenge string
	CreatedAt     time.Time
}

type HistoryEntry struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"created_at"`
	Result    *OIDCResult `json:"result"`
}

type Server struct {
	mux        *http.ServeMux
	config     *ConfigStore
	flowStates map[string]*FlowState
	flowMu     sync.Mutex
	history    []*HistoryEntry
	historyMu  sync.RWMutex
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

func (s *Server) addHistory(result *OIDCResult) string {
	id, _ := generateRandom(8)
	entry := &HistoryEntry{
		ID:        id,
		CreatedAt: time.Now(),
		Result:    result,
	}
	s.historyMu.Lock()
	s.history = append(s.history, entry)
	if len(s.history) > maxHistory {
		s.history = s.history[len(s.history)-maxHistory:]
	}
	s.historyMu.Unlock()
	return id
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

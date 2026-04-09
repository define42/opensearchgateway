// Package session stores authenticated Dashboards sessions in memory.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/define42/opensearchgateway/internal/authz"
)

const idleTTL = 30 * time.Minute

// Data holds the server-side metadata associated with one session.
type Data struct {
	User       *authz.User
	Access     []authz.Access
	Namespaces []string
	AuthHeader string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Store keeps gateway sessions in memory with idle expiration.
type Store struct {
	mu       sync.Mutex
	sessions map[string]Data
}

// NewStore constructs an empty in-memory session store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[string]Data),
	}
}

// Create allocates a new session token for data.
func (s *Store) Create(data Data) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessions == nil {
		s.sessions = make(map[string]Data)
	}

	now := time.Now()
	expiresAt := now.Add(idleTTL)
	data.CreatedAt = now
	data.ExpiresAt = expiresAt

	for attempt := 0; attempt < 5; attempt++ {
		token, err := randomToken()
		if err != nil {
			return "", time.Time{}, err
		}
		if _, exists := s.sessions[token]; exists {
			continue
		}
		s.sessions[token] = data
		return token, expiresAt, nil
	}

	return "", time.Time{}, errors.New("failed to allocate unique session token")
}

// Get returns token's session if it exists and has not expired.
func (s *Store) Get(token string) (Data, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return Data{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return Data{}, false
	}
	return session, true
}

// Touch refreshes token's idle timeout and returns the updated session.
func (s *Store) Touch(token string) (Data, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return Data{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return Data{}, false
	}

	session.ExpiresAt = time.Now().Add(idleTTL)
	s.sessions[token] = session
	return session, true
}

// Delete removes token from the session store.
func (s *Store) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// Set stores token with data, replacing any previous value.
func (s *Store) Set(token string, data Data) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]Data)
	}
	s.sessions[token] = data
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

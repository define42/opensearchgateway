package ingest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/define42/opensearchgateway/internal/authz"
)

const (
	CacheTTL          = 5 * time.Minute
	MaxIndexNameBytes = 255
	rolloverSuffix    = "-rollover"
	backingIndexSeed  = "-000001"
)

var (
	indexNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	ErrRouteNotFound = errors.New("route not found")
)

type AuthCache struct {
	mu       sync.Mutex
	now      func() time.Time
	entries  map[string]authCacheEntry
	inflight map[string]*authCacheCall
	hits     uint64
	misses   uint64
	expired  uint64
}

type AuthCacheStats struct {
	Hits    uint64
	Misses  uint64
	Expired uint64
	Entries uint64
}

type authCacheEntry struct {
	Username  string
	Access    []authz.Access
	ExpiresAt time.Time
}

type authCacheCall struct {
	done  chan struct{}
	entry authCacheEntry
	err   error
}

func NewAuthCache() *AuthCache {
	return &AuthCache{
		now: func() time.Time {
			return time.Now()
		},
		entries:  make(map[string]authCacheEntry),
		inflight: make(map[string]*authCacheCall),
	}
}

func (c *AuthCache) SetNow(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func AuthCacheKey(username, password string) string {
	sum := sha256.Sum256([]byte(username + ":" + password))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (c *AuthCache) Resolve(key string, fetch func() (string, []authz.Access, error)) (string, []authz.Access, bool, error) {
	if c == nil {
		username, access, err := fetch()
		return username, authz.CloneAccess(access), false, err
	}

	c.mu.Lock()
	now := c.currentTime()

	if entry, ok := c.entries[key]; ok {
		if !now.After(entry.ExpiresAt) {
			entry.ExpiresAt = now.Add(CacheTTL)
			c.entries[key] = entry
			c.hits++
			username := entry.Username
			access := authz.CloneAccess(entry.Access)
			c.mu.Unlock()
			return username, access, true, nil
		}

		delete(c.entries, key)
		c.expired++
	}

	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-call.done
		if call.err != nil {
			return "", nil, false, call.err
		}
		return call.entry.Username, authz.CloneAccess(call.entry.Access), false, nil
	}

	call := &authCacheCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.misses++
	c.mu.Unlock()

	username, access, err := fetch()

	c.mu.Lock()
	delete(c.inflight, key)
	if err == nil {
		call.entry = authCacheEntry{
			Username:  username,
			Access:    authz.CloneAccess(access),
			ExpiresAt: c.currentTime().Add(CacheTTL),
		}
		c.entries[key] = call.entry
	}
	call.err = err
	close(call.done)
	c.mu.Unlock()

	if err != nil {
		return "", nil, false, err
	}
	return username, authz.CloneAccess(access), false, nil
}

func (c *AuthCache) Stats() AuthCacheStats {
	if c == nil {
		return AuthCacheStats{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return AuthCacheStats{
		Hits:    c.hits,
		Misses:  c.misses,
		Expired: c.expired,
		Entries: uint64(len(c.entries)),
	}
}

func ParsePath(path string) (string, error) {
	if !strings.HasPrefix(path, "/ingest/") {
		return "", ErrRouteNotFound
	}

	indexName := strings.TrimPrefix(path, "/ingest/")
	indexName = strings.TrimSuffix(indexName, "/")
	if indexName == "" {
		return "", errors.New("path must be /ingest/<index>/")
	}
	if strings.Contains(indexName, "/") {
		return "", errors.New("path must be /ingest/<index>/")
	}
	if !ValidIndexName(indexName) {
		return "", errors.New("index name must start with a lowercase letter or digit and contain only lowercase letters, digits, '-' or '_'")
	}
	return indexName, nil
}

func DecodeJSONObject(body io.Reader) (map[string]any, error) {
	decoder := json.NewDecoder(body)

	var value any
	if err := decoder.Decode(&value); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("request body must be a JSON object")
		}
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("request body must be a JSON object")
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("request body must contain a single JSON object")
		}
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	return object, nil
}

func ParseEventTime(document map[string]any) (time.Time, error) {
	rawValue, ok := document["event_time"]
	if !ok {
		return time.Time{}, errors.New(`missing required field "event_time"`)
	}

	value, ok := rawValue.(string)
	if !ok {
		return time.Time{}, errors.New(`field "event_time" must be a string`)
	}
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New(`field "event_time" must be a UTC RFC3339 timestamp ending in "Z"`)
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New(`field "event_time" must be a valid RFC3339 timestamp`)
	}
	return parsed.UTC(), nil
}

func BuildWriteAlias(indexName string, eventTime time.Time) string {
	return fmt.Sprintf("%s-%s%s", indexName, eventTime.UTC().Format("20060102"), rolloverSuffix)
}

func BuildFirstBackingIndex(alias string) string {
	return alias + backingIndexSeed
}

func ValidIndexName(indexName string) bool {
	return indexNamePattern.MatchString(indexName)
}

func (c *AuthCache) currentTime() time.Time {
	if c == nil || c.now == nil {
		return time.Now()
	}
	return c.now()
}

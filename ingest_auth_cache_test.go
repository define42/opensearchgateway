package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngestAuthCacheCachesSuccessfulLookups(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 8, 12, 0, 0, 0, time.UTC)
	cache := newIngestAuthCache()
	cache.SetNow(func() time.Time { return now })

	lookups := 0
	key := ingestAuthCacheKey("ingestuser", "dogood")

	username, access, cached, err := cache.Resolve(key, func() (string, []Access, error) {
		lookups++
		return "ingestuser", []Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if cached {
		t.Fatal("expected first lookup to miss cache")
	}
	if username != "ingestuser" || len(access) != 1 || access[0].Namespace != "team10" {
		t.Fatalf("unexpected cached access result: username=%q access=%+v", username, access)
	}

	access[0].Namespace = "mutated"
	now = now.Add(30 * time.Second)

	username, access, cached, err = cache.Resolve(key, func() (string, []Access, error) {
		lookups++
		return "wrong", nil, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error on cached lookup: %v", err)
	}
	if !cached {
		t.Fatal("expected second lookup to hit cache")
	}
	if username != "ingestuser" || len(access) != 1 || access[0].Namespace != "team10" {
		t.Fatalf("unexpected cached access result after mutation: username=%q access=%+v", username, access)
	}
	if lookups != 1 {
		t.Fatalf("expected one LDAP lookup, got %d", lookups)
	}

	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Expired != 0 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

func TestIngestAuthCacheExpiresEntries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 8, 12, 0, 0, 0, time.UTC)
	cache := newIngestAuthCache()
	cache.SetNow(func() time.Time { return now })

	lookups := 0
	key := ingestAuthCacheKey("ingestuser", "dogood")

	if _, _, _, err := cache.Resolve(key, func() (string, []Access, error) {
		lookups++
		return "ingestuser", []Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	}); err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	now = now.Add(ingestAuthCacheTTL + time.Second)

	_, _, cached, err := cache.Resolve(key, func() (string, []Access, error) {
		lookups++
		return "ingestuser", []Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error after expiry: %v", err)
	}
	if cached {
		t.Fatal("expected expired entry to miss cache")
	}
	if lookups != 2 {
		t.Fatalf("expected two LDAP lookups after expiry, got %d", lookups)
	}

	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 2 || stats.Expired != 1 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

func TestIngestAuthCacheDeduplicatesConcurrentMisses(t *testing.T) {
	t.Parallel()

	cache := newIngestAuthCache()
	key := ingestAuthCacheKey("ingestuser", "dogood")

	var lookups atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	const goroutines = 8
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			username, access, _, err := cache.Resolve(key, func() (string, []Access, error) {
				if lookups.Add(1) == 1 {
					started <- struct{}{}
				}
				<-release
				return "ingestuser", []Access{{Group: "team10_rw", Namespace: "team10"}}, nil
			})
			if err != nil {
				errCh <- err
				return
			}
			if username != "ingestuser" || len(access) != 1 || access[0].Namespace != "team10" {
				errCh <- io.ErrUnexpectedEOF
			}
		}()
	}

	<-started
	close(release)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Resolve returned error: %v", err)
		}
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("expected one in-flight LDAP lookup, got %d", got)
	}

	stats := cache.Stats()
	if stats.Misses != 1 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

func TestGatewayIngestBasicAuthUsesLDAPCache(t *testing.T) {
	t.Parallel()

	var calls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/team10-20241230-rollover":
			w.WriteHeader(http.StatusOK)
		case "POST /team10-20241230-rollover/_doc":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"cached-doc"}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	var authCalls atomic.Int32
	gateway := newGateway(newClient(testConfig(openSearch)), func(username, password string) (*User, []Access, error) {
		authCalls.Add(1)
		return &User{Name: username, Namespace: "team10"}, []Access{
			{Group: "team10_rw", Namespace: "team10"},
		}, nil
	})

	handler := gateway.Handler()
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"cached"}`))
		request.Header.Set("Content-Type", "application/json")
		request.SetBasicAuth("ingestuser", "dogood")

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
		}

		var response ingestResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.WriteAlias != "team10-20241230-rollover" {
			t.Fatalf("unexpected write alias: %#v", response)
		}
	}

	if got := authCalls.Load(); got != 1 {
		t.Fatalf("expected one LDAP auth call, got %d", got)
	}
	if len(calls) != 4 {
		t.Fatalf("expected two alias checks and two doc writes, got %#v", calls)
	}

	stats := gateway.ingestAuthCache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Expired != 0 || stats.Entries != 1 {
		t.Fatalf("unexpected gateway cache stats: %+v", stats)
	}
}

func TestGatewayIngestBasicAuthDoesNotCacheAuthenticationErrors(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	var authCalls atomic.Int32
	gateway := newGateway(newClient(testConfig(openSearch)), func(username, password string) (*User, []Access, error) {
		authCalls.Add(1)
		return nil, nil, errLDAPInvalidCredentials
	})

	handler := gateway.Handler()
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"cached"}`))
		request.Header.Set("Content-Type", "application/json")
		request.SetBasicAuth("ingestuser", "wrong")

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
		}
	}

	if got := authCalls.Load(); got != 2 {
		t.Fatalf("expected failed LDAP auth to be retried twice, got %d", got)
	}

	stats := gateway.ingestAuthCache.Stats()
	if stats.Hits != 0 || stats.Misses != 2 || stats.Expired != 0 || stats.Entries != 0 {
		t.Fatalf("unexpected gateway cache stats after failures: %+v", stats)
	}
}

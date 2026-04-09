package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ldappkg "github.com/define42/opensearchgateway/internal/ldap"
)

func TestLDAPIngestUserCanIngestTeam10(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	var mu sync.Mutex
	var openSearchCalls []string
	var indexedDocument map[string]any
	aliasChecks := 0
	indexedDocuments := 0

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.Method + " " + r.URL.Path {
		case "GET /_plugins/_ism/policies/" + ismPolicyID:
			http.NotFound(w, r)
		case "PUT /_plugins/_ism/policies/" + ismPolicyID:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /_index_template/" + indexTemplateName:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "GET /_plugins/_security/api/tenants/team10":
			http.NotFound(w, r)
		case "PUT /_plugins/_security/api/tenants/team10":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "HEAD /_alias/team10-20241230-rollover":
			if aliasChecks == 0 {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			aliasChecks++
		case "PUT /team10-20241230-rollover-000001":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "POST /_plugins/_ism/add/team10-20241230-rollover-000001":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "POST /team10-20241230-rollover/_doc":
			indexedDocument = decodeRequestBody(t, r)
			indexedDocuments++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"ldap-team10-doc"}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	var dashboardsCalls []string
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		dashboardsCalls = append(dashboardsCalls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()

		if got := r.Header.Get("securitytenant"); got != "team10" {
			t.Fatalf("expected tenant header team10, got %q", got)
		}

		switch r.Method + " " + r.URL.RequestURI() {
		case "POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-team10?overwrite=true":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /dashboards/api/opensearch-dashboards/settings/defaultIndex":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer dashboards.Close()

	cfg := Config{
		BaseURL:            openSearch.URL,
		Username:           "admin",
		Password:           defaultPassword,
		DashboardsURL:      dashboards.URL,
		DashboardsUsername: "admin",
		DashboardsPassword: defaultPassword,
		DashboardsTenant:   defaultTenant,
		ListenAddr:         ":0",
		Shards:             2,
		Replicas:           2,
		HTTPClient:         &http.Client{Timeout: 10 * time.Second},
	}

	baseURL, gateway, stopGateway := startIntegrationGateway(ctx, t, cfg)
	defer stopGateway()

	responses := make([]ingestResponse, 0, 2)
	messages := []string{"ldap ingest integration", "ldap ingest cached"}
	for _, message := range messages {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"`+message+`"}`))
		if err != nil {
			t.Fatalf("build ingest request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("ingestuser", "dogood")

		resp, err := cfg.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("send ingest request: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read ingest response: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		var response ingestResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode ingest response: %v", err)
		}
		responses = append(responses, response)
	}

	if responses[0].WriteAlias != "team10-20241230-rollover" || responses[1].WriteAlias != "team10-20241230-rollover" {
		t.Fatalf("unexpected write aliases: %#v", responses)
	}
	if responses[0].DocumentID != "ldap-team10-doc" || responses[0].Result != "created" || !responses[0].Bootstrapped {
		t.Fatalf("unexpected first ingest response: %#v", responses[0])
	}
	if responses[1].DocumentID != "ldap-team10-doc" || responses[1].Result != "created" || responses[1].Bootstrapped {
		t.Fatalf("unexpected second ingest response: %#v", responses[1])
	}

	if got := indexedDocument["message"]; got != "ldap ingest cached" {
		t.Fatalf("unexpected indexed message: %#v", indexedDocument)
	}
	if got := indexedDocument["event_time"]; got != "2024-12-30T10:11:12Z" {
		t.Fatalf("unexpected indexed event_time: %#v", indexedDocument)
	}
	if aliasChecks != 2 {
		t.Fatalf("expected two alias checks, got %d", aliasChecks)
	}
	if indexedDocuments != 2 {
		t.Fatalf("expected two indexed documents, got %d", indexedDocuments)
	}

	if !containsCall(openSearchCalls, "POST /team10-20241230-rollover/_doc") {
		t.Fatalf("expected document ingest call, got %#v", openSearchCalls)
	}
	if !containsCall(dashboardsCalls, "POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-team10?overwrite=true") {
		t.Fatalf("expected Dashboards data view creation, got %#v", dashboardsCalls)
	}
	if len(dashboardsCalls) != 2 {
		t.Fatalf("expected tenant-scoped Dashboards setup only once, got %#v", dashboardsCalls)
	}

	stats := gateway.ingestAuthCache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Expired != 0 || stats.Entries != 1 {
		t.Fatalf("unexpected ingest auth cache stats: %+v", stats)
	}
}

func TestLDAPJohndoeCannotIngestTeam10(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	var mu sync.Mutex
	var openSearchCalls []string

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.Method + " " + r.URL.Path {
		case "GET /_plugins/_ism/policies/" + ismPolicyID:
			http.NotFound(w, r)
		case "PUT /_plugins/_ism/policies/" + ismPolicyID:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /_index_template/" + indexTemplateName:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
	}))
	defer dashboards.Close()

	cfg := Config{
		BaseURL:            openSearch.URL,
		Username:           "admin",
		Password:           defaultPassword,
		DashboardsURL:      dashboards.URL,
		DashboardsUsername: "admin",
		DashboardsPassword: defaultPassword,
		DashboardsTenant:   defaultTenant,
		ListenAddr:         ":0",
		Shards:             2,
		Replicas:           2,
		HTTPClient:         &http.Client{Timeout: 10 * time.Second},
	}

	baseURL, _, stopGateway := startIntegrationGateway(ctx, t, cfg)
	defer stopGateway()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"should be forbidden"}`))
	if err != nil {
		t.Fatalf("build ingest request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("johndoe", "dogood")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("send ingest request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read ingest response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", resp.StatusCode, string(body))
	}

	var response errorResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error != "your LDAP account is not allowed to ingest into this index" {
		t.Fatalf("unexpected error response: %#v", response)
	}

	if len(openSearchCalls) != 3 {
		t.Fatalf("expected only startup bootstrap calls, got %#v", openSearchCalls)
	}
	if containsCall(openSearchCalls, "GET /_plugins/_security/api/tenants/team10") {
		t.Fatalf("tenant creation should not happen for read-only LDAP user: %#v", openSearchCalls)
	}
	if containsCall(openSearchCalls, "POST /team10-20241230-rollover/_doc") {
		t.Fatalf("document indexing should not happen for read-only LDAP user: %#v", openSearchCalls)
	}
}

func TestLDAPAuthenticateAccessErrorScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	t.Run("invalid credentials", func(t *testing.T) {
		user, access, err := ldapAuthenticateAccess("johndoe", "wrongpass")
		if !errors.Is(err, errLDAPInvalidCredentials) {
			t.Fatalf("expected invalid credentials error, got user=%+v access=%+v err=%v", user, access, err)
		}
	})

	t.Run("unauthorized groups", func(t *testing.T) {
		user, access, err := ldapAuthenticateAccess("serviceuser", "mysecret")
		if !errors.Is(err, errLDAPUnauthorized) {
			t.Fatalf("expected unauthorized error, got user=%+v access=%+v err=%v", user, access, err)
		}
	})
}

func requireDocker(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	cmd := exec.Command("docker", "info")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("docker is not available: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

func startDockerGlauth(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()

	cfgPath := repoPath(t, "testldap", "default-config.cfg")
	certPath := repoPath(t, "testldap", "cert.pem")
	keyPath := repoPath(t, "testldap", "key.pem")
	containerName := fmt.Sprintf("opensearchgateway-ldap-test-%d", time.Now().UnixNano())

	runArgs := []string{
		"run", "--detach", "--rm",
		"--publish", "127.0.0.1::389",
		"--name", containerName,
		"--env", "GLAUTH_CONFIG=/app/config/config.cfg",
		"--volume", cfgPath + ":/app/config/config.cfg:ro",
		"--volume", certPath + ":/app/config/cert.pem:ro",
		"--volume", keyPath + ":/app/config/key.pem:ro",
		"glauth/glauth:latest",
	}
	if out, err := exec.CommandContext(ctx, "docker", runArgs...).CombinedOutput(); err != nil {
		t.Fatalf("start glauth container: %v\n%s", err, string(out))
	}

	cleanup := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = exec.CommandContext(stopCtx, "docker", "rm", "-f", containerName).CombinedOutput()
	}

	t.Cleanup(cleanup)

	port, err := dockerMappedPort(ctx, containerName, "389/tcp")
	if err != nil {
		t.Fatalf("resolve glauth mapped port: %v", err)
	}

	ldapURL := "ldaps://127.0.0.1:" + port
	waitForLDAPReady(ctx, t, ldapURL)
	return ldapURL, cleanup
}

func dockerMappedPort(ctx context.Context, containerName, containerPort string) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "docker", "port", containerName, containerPort).CombinedOutput()
		if err == nil {
			mapping := strings.TrimSpace(string(out))
			if mapping != "" {
				hostPort := mapping[strings.LastIndex(mapping, ":")+1:]
				if hostPort != "" {
					return hostPort, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timed out waiting for docker port mapping for %s", containerName)
}

func waitForLDAPReady(ctx context.Context, t *testing.T, ldapURL string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cfg := LDAPConfig{
			URL:             ldapURL,
			BaseDN:          "dc=glauth,dc=com",
			UserFilter:      "(mail=%s)",
			GroupAttribute:  "memberOf",
			GroupNamePrefix: "team",
			UserMailDomain:  "@example.com",
			StartTLS:        false,
			SkipTLSVerify:   true,
		}
		_, _, err := ldappkg.New(cfg).AuthenticateAccess("ingestuser", "dogood")
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("LDAP did not become ready: %v", ctx.Err())
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatalf("LDAP did not become ready in time")
}

func startIntegrationGateway(ctx context.Context, t *testing.T, cfg Config) (string, *Gateway, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gateway: %v", err)
	}

	baseURL := "http://" + listener.Addr().String()
	client := newClient(cfg)
	if err := client.EnsureISMPolicy(ctx, ismPolicyID, 100000000); err != nil {
		t.Fatalf("bootstrap ISM policy: %v", err)
	}
	if err := client.EnsureIndexTemplate(ctx, indexTemplateName); err != nil {
		t.Fatalf("bootstrap index template: %v", err)
	}
	gateway := newGateway(client, ldapAuthenticateAccess)
	runCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)

	go func() {
		srv := &http.Server{
			Handler:           gateway.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			<-runCtx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
		}()

		err := srv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	waitForGatewayReady(ctx, t, cfg.HTTPClient, baseURL)

	cleanup := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("gateway exited with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for gateway shutdown")
		}
	}

	return baseURL, gateway, cleanup
}

func waitForGatewayReady(ctx context.Context, t *testing.T, client *http.Client, baseURL string) {
	t.Helper()

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/login", nil)
		if err != nil {
			t.Fatalf("build readiness request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("gateway did not become ready in time")
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func repoPath(t *testing.T, elems ...string) string {
	t.Helper()

	path := filepath.Join(elems...)
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve path %q: %v", path, err)
	}
	return abs
}

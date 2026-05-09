// Package main contains gateway command and HTTP integration tests.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	authzpkg "github.com/define42/opensearchgateway/internal/authz"
	appconfig "github.com/define42/opensearchgateway/internal/config"
	ingestpkg "github.com/define42/opensearchgateway/internal/ingest"
	opensearchpkg "github.com/define42/opensearchgateway/internal/opensearch"
	serverpkg "github.com/define42/opensearchgateway/internal/server"
)

func TestDefaultHTTPClient(t *testing.T) {
	t.Setenv("OPENSEARCH_SKIP_TLS_VERIFY", "true")
	client := appconfig.DefaultHTTPClient()
	if client.Timeout != 30*time.Second {
		t.Fatalf("unexpected timeout: %v", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected TLS client config with InsecureSkipVerify, got %#v", transport.TLSClientConfig)
	}
}

func TestRunReturnsBootstrapFailures(t *testing.T) {
	t.Run("policy failure", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_ism/policies/"+opensearchpkg.DefaultISMPolicyID {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			http.Error(w, `{"error":"policy lookup failed"}`, http.StatusInternalServerError)
		}))
		defer openSearch.Close()

		calledServe := false
		err := run(context.Background(), testConfig(openSearch), func(_ http.Handler) error {
			calledServe = true
			return nil
		})
		if err == nil {
			t.Fatal("expected bootstrap error")
		}
		if calledServe {
			t.Fatal("serve should not be called when policy bootstrap fails")
		}
	})

	t.Run("template failure", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method + " " + r.URL.Path {
			case "GET /_plugins/_ism/policies/" + opensearchpkg.DefaultISMPolicyID:
				http.NotFound(w, r)
			case "PUT /_plugins/_ism/policies/" + opensearchpkg.DefaultISMPolicyID:
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{}`)
			case "PUT /_index_template/" + opensearchpkg.DefaultIndexTemplateName:
				http.Error(w, `{"error":"template failed"}`, http.StatusInternalServerError)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer openSearch.Close()

		calledServe := false
		err := run(context.Background(), testConfig(openSearch), func(_ http.Handler) error {
			calledServe = true
			return nil
		})
		if err == nil {
			t.Fatal("expected bootstrap error")
		}
		if calledServe {
			t.Fatal("serve should not be called when template bootstrap fails")
		}
	})
}

func TestGatewayRootAndDemoCoverage(t *testing.T) {
	gateway := testGatewayHandler(appconfig.Config{})
	rawGateway := newTestGateway(opensearchpkg.NewClient(appconfig.Config{}), nil)

	t.Run("root head redirects", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodHead, "/", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("expected status 303, got %d", recorder.Code)
		}
	})

	t.Run("root wrong method", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("Allow"); got != http.MethodGet+", "+http.MethodHead {
			t.Fatalf("unexpected Allow header: %q", got)
		}
	})

	t.Run("root not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/nope", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("demo path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/demo/nope", nil)
		rawGateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("login path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/login/nope", nil)
		rawGateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})
}

func TestGatewayLogoutCoverage(t *testing.T) {
	gateway := testGatewayHandler(appconfig.Config{})
	rawGateway := newTestGateway(opensearchpkg.NewClient(appconfig.Config{}), nil)

	t.Run("logout wrong method", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/logout", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("Allow"); got != http.MethodPost {
			t.Fatalf("unexpected Allow header: %q", got)
		}
	})

	t.Run("logout dangling cookie still redirects", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/logout", nil)
		request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: "dangling"})
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("expected status 303, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("Location"); got != "/login" {
			t.Fatalf("unexpected redirect: %q", got)
		}
	})

	t.Run("logout path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/logout/nope", nil)
		rawGateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})
}

func TestGatewayDashboardsCoverage(t *testing.T) {
	t.Run("path not found", func(t *testing.T) {
		gateway := newTestGateway(opensearchpkg.NewClient(appconfig.Config{}), nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/dashboards-nope", nil)
		gateway.HandleDashboards(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("proxy error returns bad gateway", func(t *testing.T) {
		gateway := newTestGateway(opensearchpkg.NewClient(appconfig.Config{DashboardsURL: "://bad"}), nil)
		encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
			User:       &authzpkg.User{Name: "alice"},
			AuthHeader: serverpkg.BuildBasicAuthorization("alice", "secret"),
		})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/dashboards", nil)
		request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})
		gateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestHandleLoginSubmitCoverage(t *testing.T) {
	t.Run("parse form failure", func(t *testing.T) {
		gateway := testGatewayHandler(appconfig.Config{})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/login", io.NopCloser(errorReader{err: errors.New("read failed")}))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d", recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "failed to read login form") {
			t.Fatalf("expected parse-form error page, got %q", recorder.Body.String())
		}
	})

	t.Run("password generation failure returns login error page", func(t *testing.T) {
		oldReader := cryptorand.Reader
		cryptorand.Reader = errorReader{err: errors.New("entropy unavailable")}
		defer func() {
			cryptorand.Reader = oldReader
		}()

		openSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}))
		defer openSearch.Close()

		dashboards := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
		}))
		defer dashboards.Close()

		gateway := testGatewayHandlerWithAuth(testConfigWithDashboards(openSearch, dashboards), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
			return &authzpkg.User{Name: username, Namespace: "team1"}, []authzpkg.Access{
				{Group: "team1_rw", Namespace: "team1"},
			}, nil
		})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "failed to allocate session credentials") {
			t.Fatalf("expected password-generation failure page, got %q", recorder.Body.String())
		}
	})
}

func TestRenderLoginPageWriterFailure(_ *testing.T) {
	writer := &failingResponseWriter{header: make(http.Header)}
	newTestGateway(opensearchpkg.NewClient(appconfig.Config{}), nil).RenderLoginPage(writer, http.StatusOK, serverpkg.LoginPageData{Username: "alice"})
}

func TestDecodeJSONObjectCoverage(t *testing.T) {
	if _, err := ingestpkg.DecodeJSONObject(strings.NewReader("")); err == nil || err.Error() != "request body must be a JSON object" {
		t.Fatalf("expected empty-body decode error, got %v", err)
	}

	if _, err := ingestpkg.DecodeJSONObject(strings.NewReader(`{} {}`)); err == nil || !strings.Contains(err.Error(), "single JSON object") {
		t.Fatalf("expected trailing-json decode error, got %v", err)
	}
}

//nolint:gocognit,funlen // Coverage subtests intentionally collect security helper edge cases.
func TestProvisionAndSecurityHelpersCoverage(t *testing.T) {
	t.Run("provision login user without access", func(t *testing.T) {
		client := opensearchpkg.NewClient(appconfig.Config{})
		if err := client.ProvisionLoginUser(context.Background(), "alice", "secret", nil); err == nil {
			t.Fatal("expected missing-access error")
		}
	})

	t.Run("provision login user rejects invalid namespace", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/internalusers/alice" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			http.NotFound(w, r)
		}))
		defer openSearch.Close()

		client := opensearchpkg.NewClient(testConfig(openSearch))
		err := client.ProvisionLoginUser(context.Background(), "alice", "secret", []authzpkg.Access{
			{Group: "bad_rw", Namespace: "bad.namespace"},
		})
		if err == nil || !strings.Contains(err.Error(), "cannot be mapped") {
			t.Fatalf("expected invalid namespace error, got %v", err)
		}
	})

	t.Run("ensure internal user writable missing user info", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"other":{"reserved":false,"hidden":false}}`)
		}))
		defer openSearch.Close()

		client := opensearchpkg.NewClient(testConfig(openSearch))
		if err := client.EnsureInternalUserWritable(context.Background(), "alice"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure internal user writable hidden user", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"alice":{"reserved":false,"hidden":true}}`)
		}))
		defer openSearch.Close()

		client := opensearchpkg.NewClient(testConfig(openSearch))
		err := client.EnsureInternalUserWritable(context.Background(), "alice")
		if !errors.Is(err, opensearchpkg.ErrReservedInternalUser) {
			t.Fatalf("expected reserved/hidden error, got %v", err)
		}
	})

	t.Run("ensure security role failure", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"role failed"}`, http.StatusInternalServerError)
		}))
		defer openSearch.Close()

		client := opensearchpkg.NewClient(testConfig(openSearch))
		if err := client.EnsureSecurityRole(context.Background(), "gateway_team1_rw", authzpkg.Access{Namespace: "team1"}); err == nil {
			t.Fatal("expected EnsureSecurityRole to fail")
		}
	})

	t.Run("upsert internal user hashes password", func(t *testing.T) {
		var body map[string]any
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		}))
		defer openSearch.Close()

		client := opensearchpkg.NewClient(testConfig(openSearch))
		if err := client.UpsertInternalUser(context.Background(), "alice", "secret", []string{"kibana_user"}, []string{"team1_rw"}, []string{"team1"}); err != nil {
			t.Fatalf("UpsertInternalUser returned error: %v", err)
		}
		if hash, ok := body["hash"].(string); !ok || hash == "" {
			t.Fatalf("expected non-empty password hash, got %#v", body["hash"])
		}
		if _, ok := body["password"]; ok {
			t.Fatalf("expected plaintext password to be omitted, got %#v", body)
		}
	})
}

//nolint:gocognit,cyclop,funlen // Coverage subtests intentionally group related dashboard client branches.
func TestTenantAndDashboardsClientCoverage(t *testing.T) {
	t.Run("ensure tenant without dashboards url is noop", func(t *testing.T) {
		client := opensearchpkg.NewClient(appconfig.Config{})
		if err := client.EnsureTenant(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure tenant cached skip", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}))
		defer openSearch.Close()

		cfg := testConfig(openSearch)
		cfg.DashboardsURL = "http://dashboards.example"
		client := opensearchpkg.NewClient(cfg)
		client.EnsuredTenants.Store("orders", true)

		if err := client.EnsureTenant(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure dashboard data view without dashboards url is noop", func(t *testing.T) {
		client := opensearchpkg.NewClient(appconfig.Config{})
		if err := client.EnsureDashboardDataView(context.Background(), "orders", "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure dashboard data view cached skip", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/_plugins/_security/api/tenants/orders" {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"orders":{"reserved":false}}`)
				return
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}))
		defer openSearch.Close()

		cfg := testConfig(openSearch)
		cfg.DashboardsURL = "http://dashboards.example"
		client := opensearchpkg.NewClient(cfg)
		client.EnsuredDataViews.Store("orders/"+opensearchpkg.BuildDataViewID("orders"), true)

		if err := client.EnsureDashboardDataView(context.Background(), "orders", "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("set dashboards default index failure", func(t *testing.T) {
		dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"nope"}`, http.StatusInternalServerError)
		}))
		defer dashboards.Close()

		client := opensearchpkg.NewClient(appconfig.Config{
			DashboardsURL:      dashboards.URL,
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
			HTTPClient:         dashboards.Client(),
		})
		err := client.SetDashboardsDefaultIndex(context.Background(), "team1", opensearchpkg.BuildDataViewID("team1"))
		if err == nil || !strings.Contains(err.Error(), `tenant "team1"`) {
			t.Fatalf("expected tenant-scoped default index error, got %v", err)
		}
	})

	t.Run("set dashboards default index if missing skips existing default", func(t *testing.T) {
		var calls []string
		dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.RequestURI())
			if r.Method != http.MethodGet || r.URL.RequestURI() != "/dashboards/api/opensearch-dashboards/settings/defaultIndex" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"settings":{"defaultIndex":{"userValue":"gateway-index-pattern-team1"}}}`)
		}))
		defer dashboards.Close()

		client := opensearchpkg.NewClient(appconfig.Config{
			DashboardsURL:      dashboards.URL,
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
			HTTPClient:         dashboards.Client(),
		})
		if err := client.SetDashboardsDefaultIndexIfMissing(context.Background(), "team1", opensearchpkg.BuildDataViewID("team1-demo")); err != nil {
			t.Fatalf("SetDashboardsDefaultIndexIfMissing returned error: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{"GET /dashboards/api/opensearch-dashboards/settings/defaultIndex"}) {
			t.Fatalf("unexpected default-index calls: %#v", calls)
		}
	})

	t.Run("set dashboards default index if missing writes empty default", func(t *testing.T) {
		var calls []string
		var body map[string]any
		dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.RequestURI())
			switch r.Method + " " + r.URL.RequestURI() {
			case "GET /dashboards/api/opensearch-dashboards/settings/defaultIndex":
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"settings":{"defaultIndex":{}}}`)
			case "POST /dashboards/api/opensearch-dashboards/settings/defaultIndex":
				body = decodeRequestBody(t, r)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{}`)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			}
		}))
		defer dashboards.Close()

		client := opensearchpkg.NewClient(appconfig.Config{
			DashboardsURL:      dashboards.URL,
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
			HTTPClient:         dashboards.Client(),
		})
		if err := client.SetDashboardsDefaultIndexIfMissing(context.Background(), "team1", opensearchpkg.BuildDataViewID("team1-demo")); err != nil {
			t.Fatalf("SetDashboardsDefaultIndexIfMissing returned error: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{
			"GET /dashboards/api/opensearch-dashboards/settings/defaultIndex",
			"POST /dashboards/api/opensearch-dashboards/settings/defaultIndex",
		}) {
			t.Fatalf("unexpected default-index calls: %#v", calls)
		}
		if got := body["value"]; got != opensearchpkg.BuildDataViewID("team1-demo") {
			t.Fatalf("unexpected default-index body: %#v", body)
		}
	})

	t.Run("do dashboards json uses default tenant", func(t *testing.T) {
		var sawTenant string
		var sawAuth string
		dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawTenant = r.Header.Get("securitytenant")
			sawAuth = r.Header.Get("Authorization")
			if r.URL.Path != "/dashboards/api/test" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		}))
		defer dashboards.Close()

		client := opensearchpkg.NewClient(appconfig.Config{
			DashboardsURL:      dashboards.URL,
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
			DashboardsTenant:   "admin_tenant",
			HTTPClient:         dashboards.Client(),
		})
		if err := client.DoDashboardsJSON(context.Background(), http.MethodPost, "/api/test", map[string]any{"hello": "world"}, nil, []int{http.StatusOK}); err != nil {
			t.Fatalf("doDashboardsJSON returned error: %v", err)
		}
		if sawTenant != "admin_tenant" {
			t.Fatalf("expected default dashboards tenant, got %q", sawTenant)
		}
		if !strings.HasPrefix(sawAuth, "Basic ") {
			t.Fatalf("expected basic auth header, got %q", sawAuth)
		}
	})

	t.Run("new dashboards request without tenant header when empty", func(t *testing.T) {
		client := opensearchpkg.NewClient(appconfig.Config{
			DashboardsURL:      "http://dashboards.example",
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
		})
		req, err := client.NewDashboardsRequest(context.Background(), http.MethodGet, "api/test", nil)
		if err != nil {
			t.Fatalf("newDashboardsRequest returned error: %v", err)
		}
		if got := req.URL.String(); got != "http://dashboards.example/dashboards/api/test" {
			t.Fatalf("unexpected dashboards url: %q", got)
		}
		if got := req.Header.Get("securitytenant"); got != "" {
			t.Fatalf("expected no tenant header, got %q", got)
		}
	})
}

func TestClientHelperCoverage(t *testing.T) {
	t.Run("alias exists returns response error on unexpected status", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"alias check failed"}`, http.StatusInternalServerError)
		}))
		defer openSearch.Close()

		client := opensearchpkg.NewClient(testConfig(openSearch))
		_, err := client.AliasExists(context.Background(), "orders-20241230-rollover")
		if err == nil {
			t.Fatal("expected aliasExists to fail")
		}

		var responseErr *opensearchpkg.ResponseError
		if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected response error with status 500, got %v", err)
		}
	})

	t.Run("do json with request returns marshal error", func(t *testing.T) {
		client := opensearchpkg.NewClient(appconfig.Config{HTTPClient: http.DefaultClient})
		err := client.DoJSONWithRequest(context.Background(), http.MethodPost, "/broken", map[string]any{"bad": make(chan int)}, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
			t.Fatal("request builder should not be called when json marshal fails")
			return nil, nil
		})
		if err == nil {
			t.Fatal("expected marshal error")
		}
	})

	t.Run("do json with request returns builder error", func(t *testing.T) {
		client := opensearchpkg.NewClient(appconfig.Config{HTTPClient: http.DefaultClient})
		wantErr := errors.New("build failed")
		err := client.DoJSONWithRequest(context.Background(), http.MethodGet, "/broken", nil, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
			return nil, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected builder error, got %v", err)
		}
	})
}

func TestDashboardsHelperCoverage(t *testing.T) {
	t.Run("dashboards helper functions", func(t *testing.T) {
		if got := opensearchpkg.DashboardsAPIPath("/dashboards"); got != "/dashboards" {
			t.Fatalf("unexpected dashboards path: %q", got)
		}
		if got := opensearchpkg.DashboardsAPIPath("/api/test"); got != "/dashboards/api/test" {
			t.Fatalf("unexpected dashboards path: %q", got)
		}
		if got := opensearchpkg.DashboardsAPIPath("api/test"); got != "/dashboards/api/test" {
			t.Fatalf("unexpected dashboards path: %q", got)
		}
	})
}

func TestDecodeAndSessionHelpersCoverage(t *testing.T) {
	t.Run("secure cookie max age matches browser cookie", func(t *testing.T) {
		gateway := newTestGateway(opensearchpkg.NewClient(appconfig.Config{}), nil)
		maxAge := reflect.ValueOf(gateway.SecureCookie).Elem().FieldByName("maxAge").Int()
		if maxAge != 86400 {
			t.Fatalf("expected securecookie server-side max age to be 86400 seconds, got %d", maxAge)
		}
	})

	t.Run("forwarded proto handles https", func(t *testing.T) {
		if got := serverpkg.ForwardedProto(httptest.NewRequest(http.MethodGet, "http://example.com", nil)); got != "http" {
			t.Fatalf("expected http proto, got %q", got)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.TLS = &tls.ConnectionState{}
		if got := serverpkg.ForwardedProto(req); got != "https" {
			t.Fatalf("expected https proto, got %q", got)
		}
	})
}

func TestAccessGroupNamesAndRetryableConflict(t *testing.T) {
	names := authzpkg.AccessGroupNames([]authzpkg.Access{
		{Group: "team1_rw"},
		{Group: ""},
		{Group: "team1_rw"},
		{Group: "team2_r"},
	})
	if !reflect.DeepEqual(names, []string{"team1_rw", "team2_r"}) {
		t.Fatalf("unexpected deduped group names: %#v", names)
	}

	if !opensearchpkg.IsRetryableBootstrapConflict(&opensearchpkg.ResponseError{StatusCode: http.StatusBadRequest, Body: `{"error":{"type":"resource_already_exists_exception"}}`}) {
		t.Fatal("expected 400 resource_already_exists_exception to be retryable")
	}
	if opensearchpkg.IsRetryableBootstrapConflict(errors.New("plain error")) {
		t.Fatal("expected plain error not to be retryable")
	}
}

type failingResponseWriter struct {
	header http.Header
	status int
}

func (w *failingResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	if r.err == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, r.err
}

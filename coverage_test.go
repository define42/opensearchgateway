package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultHTTPClientAndGetenv(t *testing.T) {
	t.Setenv("OPENSEARCH_SKIP_TLS_VERIFY", "true")
	client := defaultHTTPClient()
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

	t.Setenv("GATEWAY_TEST_ENV", "")
	if got := getenv("GATEWAY_TEST_ENV", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback getenv value, got %q", got)
	}
	t.Setenv("GATEWAY_TEST_ENV", "configured")
	if got := getenv("GATEWAY_TEST_ENV", "fallback"); got != "configured" {
		t.Fatalf("expected configured getenv value, got %q", got)
	}
}

func TestMustParse(t *testing.T) {
	parsed := mustParse("https://example.com/base")
	if parsed.Scheme != "https" || parsed.Host != "example.com" || parsed.Path != "/base" {
		t.Fatalf("unexpected parsed URL: %#v", parsed)
	}
}

func TestRunReturnsBootstrapFailures(t *testing.T) {
	t.Run("policy failure", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_ism/policies/"+ismPolicyID {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			http.Error(w, `{"error":"policy lookup failed"}`, http.StatusInternalServerError)
		}))
		defer openSearch.Close()

		calledServe := false
		err := run(context.Background(), testConfig(openSearch), func(handler http.Handler) error {
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
			case "GET /_plugins/_ism/policies/" + ismPolicyID:
				http.NotFound(w, r)
			case "PUT /_plugins/_ism/policies/" + ismPolicyID:
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{}`)
			case "PUT /_index_template/" + indexTemplateName:
				http.Error(w, `{"error":"template failed"}`, http.StatusInternalServerError)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer openSearch.Close()

		calledServe := false
		err := run(context.Background(), testConfig(openSearch), func(handler http.Handler) error {
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
	gateway := testGatewayHandler(Config{})
	rawGateway := newGateway(newClient(Config{}), nil)

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
		rawGateway.handleDemo(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("login path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/login/nope", nil)
		rawGateway.handleLogin(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})
}

func TestGatewayLogoutCoverage(t *testing.T) {
	gateway := testGatewayHandler(Config{})
	rawGateway := newGateway(newClient(Config{}), nil)

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
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "dangling"})
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
		rawGateway.handleLogout(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})
}

func TestGatewayDashboardsCoverage(t *testing.T) {
	t.Run("path not found", func(t *testing.T) {
		gateway := newGateway(newClient(Config{}), nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/dashboards-nope", nil)
		gateway.handleDashboards(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("proxy error returns bad gateway", func(t *testing.T) {
		gateway := newGateway(newClient(Config{DashboardsURL: "://bad"}), nil)
		token, expiresAt, err := gateway.sessions.Create(sessionData{
			User:       &User{Name: "alice"},
			Namespaces: []string{"team1"},
			AuthHeader: buildBasicAuthorization("alice", "secret"),
		})
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/dashboards", nil)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})
		gateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestHandleLoginSubmitCoverage(t *testing.T) {
	t.Run("parse form failure", func(t *testing.T) {
		gateway := testGatewayHandler(Config{})
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

	t.Run("password hash failure returns login error page", func(t *testing.T) {
		oldReader := cryptorand.Reader
		cryptorand.Reader = errorReader{err: errors.New("entropy unavailable")}
		defer func() {
			cryptorand.Reader = oldReader
		}()

		var openSearchCalls []string
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)

			switch r.Method + " " + r.URL.Path {
			case "GET /_plugins/_security/api/internalusers/testuser":
				http.NotFound(w, r)
			case "PUT /_plugins/_security/api/roles/gateway_team1_rw":
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{}`)
			case "GET /_plugins/_security/api/tenants/team1":
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"team1":{"reserved":false}}`)
			case "PUT /_plugins/_security/api/internalusers/testuser":
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{}`)
			default:
				t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer openSearch.Close()

		dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method + " " + r.URL.RequestURI() {
			case "POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-team1?overwrite=true":
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

		gateway := testGatewayHandlerWithAuth(testConfigWithDashboards(openSearch, dashboards), func(username, password string) (*User, []Access, error) {
			return &User{Name: username, Namespace: "team1"}, []Access{
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
		if !strings.Contains(recorder.Body.String(), `hash OpenSearch password for &#34;testuser&#34;: entropy unavailable`) {
			t.Fatalf("expected hash failure error page, got %q", recorder.Body.String())
		}
		if !reflect.DeepEqual(openSearchCalls, []string{
			"GET /_plugins/_security/api/internalusers/testuser",
			"PUT /_plugins/_security/api/roles/gateway_team1_rw",
			"GET /_plugins/_security/api/tenants/team1",
		}) {
			t.Fatalf("unexpected OpenSearch sequence: %#v", openSearchCalls)
		}
	})
}

func TestRenderLoginPageWriterFailure(t *testing.T) {
	gateway := testGatewayHandler(Config{}).(*http.ServeMux)
	_ = gateway

	writer := &failingResponseWriter{header: make(http.Header)}
	newGateway(newClient(Config{}), nil).renderLoginPage(writer, http.StatusOK, loginPageData{Username: "alice"})
}

func TestDecodeJSONObjectCoverage(t *testing.T) {
	if _, err := decodeJSONObject(strings.NewReader("")); err == nil || err.Error() != "request body must be a JSON object" {
		t.Fatalf("expected empty-body decode error, got %v", err)
	}

	if _, err := decodeJSONObject(strings.NewReader(`{} {}`)); err == nil || !strings.Contains(err.Error(), "single JSON object") {
		t.Fatalf("expected trailing-json decode error, got %v", err)
	}
}

func TestProvisionAndSecurityHelpersCoverage(t *testing.T) {
	t.Run("provision login user without access", func(t *testing.T) {
		client := newClient(Config{})
		if _, err := client.ProvisionLoginUser(context.Background(), "alice", "secret", nil); err == nil {
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

		client := newClient(testConfig(openSearch))
		_, err := client.ProvisionLoginUser(context.Background(), "alice", "secret", []Access{
			{Group: "bad_rw", Namespace: "bad.namespace"},
		})
		if err == nil || !strings.Contains(err.Error(), "cannot be mapped") {
			t.Fatalf("expected invalid namespace error, got %v", err)
		}
	})

	t.Run("ensure internal user writable missing user info", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"other":{"reserved":false,"hidden":false}}`)
		}))
		defer openSearch.Close()

		client := newClient(testConfig(openSearch))
		if err := client.ensureInternalUserWritable(context.Background(), "alice"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure internal user writable hidden user", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"alice":{"reserved":false,"hidden":true}}`)
		}))
		defer openSearch.Close()

		client := newClient(testConfig(openSearch))
		err := client.ensureInternalUserWritable(context.Background(), "alice")
		if !errors.Is(err, errReservedInternalUser) {
			t.Fatalf("expected reserved/hidden error, got %v", err)
		}
	})

	t.Run("ensure security role failure", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"role failed"}`, http.StatusInternalServerError)
		}))
		defer openSearch.Close()

		client := newClient(testConfig(openSearch))
		if err := client.EnsureSecurityRole(context.Background(), "gateway_team1_rw", Access{Namespace: "team1"}); err == nil {
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

		client := newClient(testConfig(openSearch))
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

func TestTenantAndDashboardsClientCoverage(t *testing.T) {
	t.Run("ensure tenant without dashboards url is noop", func(t *testing.T) {
		client := newClient(Config{})
		if err := client.EnsureTenant(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure tenant cached skip", func(t *testing.T) {
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}))
		defer openSearch.Close()

		cfg := testConfig(openSearch)
		cfg.DashboardsURL = "http://dashboards.example"
		client := newClient(cfg)
		client.ensuredTenants.Store("orders", true)

		if err := client.EnsureTenant(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure dashboard data view without dashboards url is noop", func(t *testing.T) {
		client := newClient(Config{})
		if err := client.EnsureDashboardDataView(context.Background(), "orders"); err != nil {
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
		client := newClient(cfg)
		client.ensuredDataViews.Store("orders/"+buildDataViewID("orders"), true)

		if err := client.EnsureDashboardDataView(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("set dashboards default index failure", func(t *testing.T) {
		dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"nope"}`, http.StatusInternalServerError)
		}))
		defer dashboards.Close()

		client := newClient(Config{
			DashboardsURL:      dashboards.URL,
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
			HTTPClient:         dashboards.Client(),
		})
		err := client.setDashboardsDefaultIndex(context.Background(), "team1", buildDataViewID("team1"))
		if err == nil || !strings.Contains(err.Error(), `tenant "team1"`) {
			t.Fatalf("expected tenant-scoped default index error, got %v", err)
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

		client := newClient(Config{
			DashboardsURL:      dashboards.URL,
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
			DashboardsTenant:   "admin_tenant",
			HTTPClient:         dashboards.Client(),
		})
		if err := client.doDashboardsJSON(context.Background(), http.MethodPost, "/api/test", map[string]any{"hello": "world"}, nil, []int{http.StatusOK}); err != nil {
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
		client := newClient(Config{
			DashboardsURL:      "http://dashboards.example",
			DashboardsUsername: "admin",
			DashboardsPassword: "secret",
		})
		req, err := client.newDashboardsRequest(context.Background(), http.MethodGet, "api/test", nil)
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
		openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"alias check failed"}`, http.StatusInternalServerError)
		}))
		defer openSearch.Close()

		client := newClient(testConfig(openSearch))
		_, err := client.aliasExists(context.Background(), "orders-20241230-rollover")
		if err == nil {
			t.Fatal("expected aliasExists to fail")
		}

		var responseErr *ResponseError
		if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected response error with status 500, got %v", err)
		}
	})

	t.Run("do json with request returns marshal error", func(t *testing.T) {
		client := newClient(Config{HTTPClient: http.DefaultClient})
		err := client.doJSONWithRequest(context.Background(), http.MethodPost, "/broken", map[string]any{"bad": make(chan int)}, nil, []int{http.StatusOK}, func(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
			t.Fatal("request builder should not be called when json marshal fails")
			return nil, nil
		})
		if err == nil {
			t.Fatal("expected marshal error")
		}
	})

	t.Run("do json with request returns builder error", func(t *testing.T) {
		client := newClient(Config{HTTPClient: http.DefaultClient})
		wantErr := errors.New("build failed")
		err := client.doJSONWithRequest(context.Background(), http.MethodGet, "/broken", nil, nil, []int{http.StatusOK}, func(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
			return nil, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected builder error, got %v", err)
		}
	})
}

func TestDashboardsResponseAndHelperCoverage(t *testing.T) {
	gateway := newGateway(newClient(Config{}), nil)

	t.Run("modify dashboards response invalid json is preserved", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?type=index-pattern", nil)
		req.Header.Set("securitytenant", "team1")
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("not-json")),
			Request:    req,
		}

		if err := gateway.modifyDashboardsResponse(resp, sessionData{Namespaces: []string{"team1"}}); err != nil {
			t.Fatalf("modifyDashboardsResponse returned error: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "not-json" {
			t.Fatalf("expected original body to be preserved, got %q", string(body))
		}
	})

	t.Run("modify dashboards response page greater than one synthesizes empty page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?type=index-pattern&search=*team1*", nil)
		req.Header.Set("securitytenant", "team1")
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"page":2,"per_page":10000,"total":0,"saved_objects":[]}`)),
			Request:    req,
		}

		if err := gateway.modifyDashboardsResponse(resp, sessionData{Namespaces: []string{"team1"}}); err != nil {
			t.Fatalf("modifyDashboardsResponse returned error: %v", err)
		}

		var payload dashboardsFindResponse
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatalf("decode modified response: %v", err)
		}
		if payload.Total != 1 || len(payload.SavedObjects) != 0 {
			t.Fatalf("expected synthesized empty page, got %#v", payload)
		}
	})

	t.Run("modify dashboards response ignores unauthorized tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?type=index-pattern", nil)
		req.Header.Set("securitytenant", "team1")
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"page":1,"per_page":10000,"total":0,"saved_objects":[]}`)),
			Request:    req,
		}

		if err := gateway.modifyDashboardsResponse(resp, sessionData{Namespaces: []string{"team2"}}); err != nil {
			t.Fatalf("modifyDashboardsResponse returned error: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `"total":0`) {
			t.Fatalf("expected body to remain unchanged, got %q", string(body))
		}
	})

	t.Run("dashboards helper functions", func(t *testing.T) {
		if got := dashboardsAPIPath("/dashboards"); got != "/dashboards" {
			t.Fatalf("unexpected dashboards path: %q", got)
		}
		if got := dashboardsAPIPath("/api/test"); got != "/dashboards/api/test" {
			t.Fatalf("unexpected dashboards path: %q", got)
		}
		if got := dashboardsAPIPath("api/test"); got != "/dashboards/api/test" {
			t.Fatalf("unexpected dashboards path: %q", got)
		}

		if isDashboardsIndexPatternFindRequest(nil) {
			t.Fatal("nil request should not match index-pattern _find")
		}
		req := httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?type=search", nil)
		if isDashboardsIndexPatternFindRequest(req) {
			t.Fatal("non-index-pattern _find should not match")
		}
		req = httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?type=index-pattern", nil)
		if !isDashboardsIndexPatternFindRequest(req) {
			t.Fatal("index-pattern _find should match")
		}

		if !matchesIndexPatternFindQuery(url.Values{}, "team1") {
			t.Fatal("empty search should match")
		}
		if !matchesIndexPatternFindQuery(url.Values{"search": []string{"*team1*"}}, "team1") {
			t.Fatal("tenant search should match")
		}
		if !matchesIndexPatternFindQuery(url.Values{"search": []string{"*gateway-index-pattern-team1*"}}, "team1") {
			t.Fatal("data-view id search should match")
		}
		if matchesIndexPatternFindQuery(url.Values{"search": []string{"*orders*"}}, "team1") {
			t.Fatal("unrelated search should not match")
		}

		if !sessionHasNamespace(sessionData{Namespaces: []string{" team1 ", "team2"}}, "team1") {
			t.Fatal("expected session to contain team1")
		}
		if sessionHasNamespace(sessionData{Namespaces: []string{"team2"}}, "team1") {
			t.Fatal("expected session not to contain team1")
		}
	})
}

func TestDecodeAndSessionHelpersCoverage(t *testing.T) {
	t.Run("session store create and touch branches", func(t *testing.T) {
		store := newSessionStore()
		token, expiresAt, err := store.Create(sessionData{User: &User{Name: "alice"}})
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}
		if token == "" || expiresAt.IsZero() {
			t.Fatalf("expected created session token and expiry, got token=%q expires=%v", token, expiresAt)
		}

		if _, ok := store.Touch("missing"); ok {
			t.Fatal("expected missing session touch to fail")
		}

		store.Set("expired", sessionData{ExpiresAt: time.Now().Add(-time.Minute)})
		if _, ok := store.Touch("expired"); ok {
			t.Fatal("expected expired session touch to fail")
		}
		if _, ok := store.Get("expired"); ok {
			t.Fatal("expected expired session to be removed")
		}
	})

	t.Run("random token success", func(t *testing.T) {
		token, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken returned error: %v", err)
		}
		if token == "" {
			t.Fatal("expected non-empty token")
		}
	})

	t.Run("forwarded proto handles https", func(t *testing.T) {
		if got := forwardedProto(httptest.NewRequest(http.MethodGet, "http://example.com", nil)); got != "http" {
			t.Fatalf("expected http proto, got %q", got)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.TLS = &tls.ConnectionState{}
		if got := forwardedProto(req); got != "https" {
			t.Fatalf("expected https proto, got %q", got)
		}
	})
}

func TestAccessGroupNamesAndRetryableConflict(t *testing.T) {
	names := accessGroupNames([]Access{
		{Group: "team1_rw"},
		{Group: ""},
		{Group: "team1_rw"},
		{Group: "team2_r"},
	})
	if !reflect.DeepEqual(names, []string{"team1_rw", "team2_r"}) {
		t.Fatalf("unexpected deduped group names: %#v", names)
	}

	if !isRetryableBootstrapConflict(&ResponseError{StatusCode: http.StatusBadRequest, Body: `{"error":{"type":"resource_already_exists_exception"}}`}) {
		t.Fatal("expected 400 resource_already_exists_exception to be retryable")
	}
	if isRetryableBootstrapConflict(errors.New("plain error")) {
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

func (w *failingResponseWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

type errorReader struct {
	err error
}

func (r errorReader) Read(p []byte) (int, error) {
	if r.err == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, r.err
}

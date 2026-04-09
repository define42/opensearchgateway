package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunBootstrapsBeforeServe(t *testing.T) {
	t.Parallel()

	var calls []string
	var policyBody map[string]any
	var templateBody map[string]any

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /_plugins/_ism/policies/" + ismPolicyID:
			calls = append(calls, "policy")
			http.NotFound(w, r)
		case "PUT /_plugins/_ism/policies/" + ismPolicyID:
			calls = append(calls, "policy-put")
			policyBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
		case "PUT /_index_template/" + indexTemplateName:
			calls = append(calls, "template")
			templateBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected bootstrap request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	sentinel := errors.New("stop serve")
	err := run(context.Background(), testConfig(openSearch), func(handler http.Handler) error {
		if handler == nil {
			t.Fatal("expected handler to be constructed")
		}
		if !reflect.DeepEqual(calls, []string{"policy", "policy-put", "template"}) {
			t.Fatalf("unexpected bootstrap order: %#v", calls)
		}

		template := nestedMap(t, templateBody["template"])
		mappings := nestedMap(t, template["mappings"])
		properties := nestedMap(t, mappings["properties"])
		eventTime := nestedMap(t, properties["event_time"])
		if got := eventTime["type"]; got != "date" {
			t.Fatalf("expected event_time mapping to be date, got %#v", got)
		}

		patterns, ok := templateBody["index_patterns"].([]any)
		if !ok || len(patterns) != 1 || patterns[0] != "*-*-rollover-*" {
			t.Fatalf("unexpected index_patterns: %#v", templateBody["index_patterns"])
		}

		policy := nestedMap(t, policyBody["policy"])
		states, ok := policy["states"].([]any)
		if !ok || len(states) == 0 {
			t.Fatalf("expected policy states, got %#v", policyBody)
		}

		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

func TestEnsureISMPolicySkipsWhenExistingMatches(t *testing.T) {
	t.Parallel()

	var calls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_ism/policies/"+ismPolicyID {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ismPolicyResponse{
			SeqNo:       7,
			PrimaryTerm: 1,
			Policy:      buildISMPolicy(100000000),
		})
	}))
	defer openSearch.Close()

	client := newClient(testConfig(openSearch))
	if err := client.EnsureISMPolicy(context.Background(), ismPolicyID, 100000000); err != nil {
		t.Fatalf("EnsureISMPolicy returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{"GET /_plugins/_ism/policies/" + ismPolicyID}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}
}

func TestEnsureISMPolicyUpdatesWhenExistingDiffers(t *testing.T) {
	t.Parallel()

	var calls []string
	var updateBody map[string]any

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())

		switch len(calls) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_ism/policies/"+ismPolicyID {
				t.Fatalf("unexpected first request: %s %s", r.Method, r.URL.RequestURI())
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ismPolicyResponse{
				SeqNo:       11,
				PrimaryTerm: 2,
				Policy:      buildISMPolicy(10),
			})
		case 2:
			expectedPath := "/_plugins/_ism/policies/" + ismPolicyID + "?if_seq_no=11&if_primary_term=2"
			if r.Method != http.MethodPut || r.URL.RequestURI() != expectedPath {
				t.Fatalf("unexpected second request: %s %s", r.Method, r.URL.RequestURI())
			}
			updateBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer openSearch.Close()

	client := newClient(testConfig(openSearch))
	if err := client.EnsureISMPolicy(context.Background(), ismPolicyID, 100000000); err != nil {
		t.Fatalf("EnsureISMPolicy returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{
		"GET /_plugins/_ism/policies/" + ismPolicyID,
		"PUT /_plugins/_ism/policies/" + ismPolicyID + "?if_seq_no=11&if_primary_term=2",
	}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}

	policy := nestedMap(t, updateBody["policy"])
	states, ok := policy["states"].([]any)
	if !ok || len(states) != 1 {
		t.Fatalf("unexpected updated policy body: %#v", updateBody)
	}
}

func TestEnsureTenantCreatesWhenMissing(t *testing.T) {
	t.Parallel()

	var calls []string
	var createBody map[string]any

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch len(calls) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
				t.Fatalf("unexpected first request: %s %s", r.Method, r.URL.Path)
			}
			http.NotFound(w, r)
		case 2:
			if r.Method != http.MethodPut || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
				t.Fatalf("unexpected second request: %s %s", r.Method, r.URL.Path)
			}
			createBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	cfg := testConfig(openSearch)
	cfg.DashboardsURL = "http://dashboards.example"

	client := newClient(cfg)
	if err := client.EnsureTenant(context.Background(), "orders"); err != nil {
		t.Fatalf("EnsureTenant returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{
		"GET /_plugins/_security/api/tenants/orders",
		"PUT /_plugins/_security/api/tenants/orders",
	}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}
	if got := createBody["description"]; got != "Gateway tenant for orders" {
		t.Fatalf("unexpected tenant description: %#v", got)
	}
}

func TestEnsureTenantSkipsWhenExisting(t *testing.T) {
	t.Parallel()

	var calls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"orders":{"reserved":false}}`)
	}))
	defer openSearch.Close()

	cfg := testConfig(openSearch)
	cfg.DashboardsURL = "http://dashboards.example"

	client := newClient(cfg)
	if err := client.EnsureTenant(context.Background(), "orders"); err != nil {
		t.Fatalf("EnsureTenant returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{"GET /_plugins/_security/api/tenants/orders"}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}
}

func TestEnsureTenantReturnsErrorOnFailure(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"tenant lookup failed"}`, http.StatusInternalServerError)
	}))
	defer openSearch.Close()

	cfg := testConfig(openSearch)
	cfg.DashboardsURL = "http://dashboards.example"

	client := newClient(cfg)
	if err := client.EnsureTenant(context.Background(), "orders"); err == nil {
		t.Fatal("expected EnsureTenant to fail")
	}
}

func TestEnsureDashboardDataViewCreatesExpectedPattern(t *testing.T) {
	t.Parallel()

	var openSearchCalls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"orders":{"reserved":false}}`)
	}))
	defer openSearch.Close()

	var requestBody map[string]any
	var defaultIndexBody map[string]any
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("osd-xsrf"); got != "true" {
			t.Fatalf("expected osd-xsrf header, got %q", got)
		}
		if got := r.Header.Get("securitytenant"); got != "orders" {
			t.Fatalf("expected securitytenant header, got %q", got)
		}
		switch r.Method + " " + r.URL.RequestURI() {
		case "POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true":
			requestBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /dashboards/api/opensearch-dashboards/settings/defaultIndex":
			defaultIndexBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer dashboards.Close()

	client := newClient(testConfigWithDashboards(openSearch, dashboards))

	if err := client.EnsureDashboardDataView(context.Background(), "orders"); err != nil {
		t.Fatalf("EnsureDashboardDataView returned error: %v", err)
	}

	if !reflect.DeepEqual(openSearchCalls, []string{
		"GET /_plugins/_security/api/tenants/orders",
	}) {
		t.Fatalf("unexpected OpenSearch request sequence: %#v", openSearchCalls)
	}

	attributes := nestedMap(t, requestBody["attributes"])
	if got := attributes["title"]; got != "orders-*" {
		t.Fatalf("unexpected data view title: %#v", got)
	}
	if got := attributes["timeFieldName"]; got != "event_time" {
		t.Fatalf("unexpected time field: %#v", got)
	}
	if got := defaultIndexBody["value"]; got != "gateway-index-pattern-orders" {
		t.Fatalf("unexpected default index body: %#v", defaultIndexBody)
	}
}

func TestGatewayIngestEnsuresDashboardDataView(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var calls []string
	appendCall := func(call string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call)
	}

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /_plugins/_security/api/tenants/orders":
			appendCall("tenant-get")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"orders":{"reserved":false}}`)
		case "HEAD /_alias/orders-20241230-rollover":
			appendCall("alias-head")
			w.WriteHeader(http.StatusOK)
		case "POST /orders-20241230-rollover/_doc":
			appendCall("doc-post")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"dash-view"}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("securitytenant"); got != "orders" {
			t.Fatalf("expected securitytenant header, got %q", got)
		}
		switch r.Method + " " + r.URL.RequestURI() {
		case "POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true":
			appendCall("data-view-post")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /dashboards/api/opensearch-dashboards/settings/defaultIndex":
			appendCall("default-index-post")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer dashboards.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfigWithDashboards(openSearch, dashboards)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"tenant-get",
		"data-view-post",
		"default-index-post",
		"alias-head",
		"doc-post",
	}) {
		t.Fatalf("unexpected request order: %#v", calls)
	}
}

func TestGatewayRootRedirectsToLogin(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
	}
}

func TestGatewayLoginServesLoginForm(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("expected HTML content type, got %q", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "<form") || !strings.Contains(body, "Username") || !strings.Contains(body, "Password") {
		t.Fatalf("expected login form content, got %q", body)
	}
}

func TestGatewayLoginRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/login", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet+", "+http.MethodPost {
		t.Fatalf("expected Allow header for login, got %q", got)
	}
}

func TestGatewayDemoServesDemoForm(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/demo", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("expected HTML content type, got %q", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "<form") || !strings.Contains(body, "Index Name") || !strings.Contains(body, "JSON Payload") {
		t.Fatalf("expected demo form content, got %q", body)
	}
	if !strings.Contains(body, "LDAP Username") || !strings.Contains(body, "LDAP Password") {
		t.Fatalf("expected demo page to include LDAP credential fields, got %q", body)
	}
	if !strings.Contains(body, "/ingest/") {
		t.Fatalf("expected demo page to reference ingest endpoint, got %q", body)
	}
}

func TestGatewayDemoRejectsNonGet(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/demo", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("expected Allow header %q, got %q", http.MethodGet, got)
	}
}

func TestGatewayIngestBasePathReturnsNotFound(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", recorder.Code)
	}
}

func TestGatewayAuthenticatedLoginRedirectsToDashboards(t *testing.T) {
	t.Parallel()

	gateway := newGateway(newClient(Config{}), nil)
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "alice"},
		Namespaces: []string{"team1"},
		AuthHeader: buildBasicAuthorization("alice", "secret"),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/dashboards/" {
		t.Fatalf("expected redirect to /dashboards/, got %q", got)
	}
}

func TestGatewayLoginInvalidCredentialsReturnsUnauthorized(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	gateway := testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return nil, nil, errLDAPInvalidCredentials
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=wrong"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Header().Get("Set-Cookie"), sessionCookieName+"=") {
		t.Fatalf("did not expect session cookie on failed login")
	}
}

func TestGatewayLoginUnauthorizedGroupsReturnsForbidden(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	gateway := testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return nil, nil, errLDAPUnauthorized
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayLoginLDAPFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	gateway := testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return nil, nil, errors.New("ldap server unavailable")
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayLoginReservedInternalUserReturnsForbidden(t *testing.T) {
	t.Parallel()

	var openSearchCalls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/internalusers/testuser" {
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"testuser":{"reserved":true,"hidden":false}}`)
	}))
	defer openSearch.Close()

	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.Path)
	}))
	defer dashboards.Close()

	gateway := testGatewayHandlerWithAuth(testConfigWithDashboards(openSearch, dashboards), func(username, password string) (*User, []Access, error) {
		return &User{Name: username, Namespace: "team1", PullOnly: false, DeleteAllowed: true}, []Access{
			{Group: "team1_rwd", Namespace: "team1", PullOnly: false, DeleteAllowed: true},
		}, nil
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(openSearchCalls, []string{
		"GET /_plugins/_security/api/internalusers/testuser",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", openSearchCalls)
	}
}

func TestGatewayLoginSuccessProvisionsUserAndSession(t *testing.T) {
	t.Parallel()

	var openSearchCalls []string
	var roleBody map[string]any
	var tenantBody map[string]any
	var userBody map[string]any

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "GET /_plugins/_security/api/internalusers/testuser":
			http.NotFound(w, r)
		case "PUT /_plugins/_security/api/roles/gateway_team1_rwd":
			roleBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "GET /_plugins/_security/api/tenants/team1":
			http.NotFound(w, r)
		case "PUT /_plugins/_security/api/tenants/team1":
			tenantBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /_plugins/_security/api/internalusers/testuser":
			userBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	var dashboardsCalls []string
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dashboardsCalls = append(dashboardsCalls, r.Method+" "+r.URL.RequestURI())

		if got := r.Header.Get("securitytenant"); got != "team1" {
			t.Fatalf("expected securitytenant header, got %q", got)
		}
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
		return &User{Name: username, Namespace: "team1", PullOnly: false, DeleteAllowed: true}, []Access{
			{Group: "team1_rwd", Namespace: "team1", PullOnly: false, DeleteAllowed: true},
		}, nil
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/dashboards/" {
		t.Fatalf("expected redirect to /dashboards/, got %q", got)
	}
	if !strings.Contains(recorder.Header().Get("Set-Cookie"), sessionCookieName+"=") {
		t.Fatalf("expected session cookie, got %q", recorder.Header().Get("Set-Cookie"))
	}

	if !reflect.DeepEqual(openSearchCalls, []string{
		"GET /_plugins/_security/api/internalusers/testuser",
		"PUT /_plugins/_security/api/roles/gateway_team1_rwd",
		"GET /_plugins/_security/api/tenants/team1",
		"PUT /_plugins/_security/api/tenants/team1",
		"PUT /_plugins/_security/api/internalusers/testuser",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", openSearchCalls)
	}
	if !reflect.DeepEqual(dashboardsCalls, []string{
		"POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-team1?overwrite=true",
		"POST /dashboards/api/opensearch-dashboards/settings/defaultIndex",
	}) {
		t.Fatalf("unexpected Dashboards sequence: %#v", dashboardsCalls)
	}

	clusterPermissions, ok := roleBody["cluster_permissions"].([]any)
	if !ok || len(clusterPermissions) == 0 {
		t.Fatalf("expected cluster permissions, got %#v", roleBody)
	}
	if !reflect.DeepEqual(clusterPermissions, []any{"cluster_composite_ops", "indices_monitor", "cluster:admin/opensearch/ql/datasources/read"}) {
		t.Fatalf("unexpected cluster permissions: %#v", clusterPermissions)
	}
	indexPermissions, ok := roleBody["index_permissions"].([]any)
	if !ok || len(indexPermissions) != 2 {
		t.Fatalf("expected index permissions, got %#v", roleBody)
	}
	indexPermission := nestedMap(t, indexPermissions[0])
	if got := indexPermission["allowed_actions"]; !reflect.DeepEqual(got, []any{"crud"}) {
		t.Fatalf("unexpected allowed actions: %#v", got)
	}
	resolvePermission := nestedMap(t, indexPermissions[1])
	if got := resolvePermission["index_patterns"]; !reflect.DeepEqual(got, []any{"*"}) {
		t.Fatalf("unexpected resolve index patterns: %#v", got)
	}
	if got := resolvePermission["allowed_actions"]; !reflect.DeepEqual(got, []any{"indices:admin/resolve/index"}) {
		t.Fatalf("unexpected resolve index actions: %#v", got)
	}
	tenantPermissions, ok := roleBody["tenant_permissions"].([]any)
	if !ok || len(tenantPermissions) != 1 {
		t.Fatalf("expected tenant permissions, got %#v", roleBody)
	}
	tenantPermission := nestedMap(t, tenantPermissions[0])
	if got := tenantPermission["allowed_actions"]; !reflect.DeepEqual(got, []any{"kibana_all_write"}) {
		t.Fatalf("unexpected tenant actions: %#v", got)
	}
	if got := tenantBody["description"]; got != "Gateway tenant for team1" {
		t.Fatalf("unexpected tenant description: %#v", got)
	}
	if got, exists := userBody["password"]; exists {
		t.Fatalf("expected hashed OpenSearch password payload, got plaintext field %#v", got)
	}
	hash, ok := userBody["hash"].(string)
	if !ok || hash == "" {
		t.Fatalf("expected OpenSearch password hash, got %#v", userBody["hash"])
	}
	if strings.Contains(hash, "dogood") {
		t.Fatalf("expected hashed OpenSearch password, got %#v", hash)
	}
	if got := userBody["opendistro_security_roles"]; !reflect.DeepEqual(got, []any{"kibana_user", "gateway_team1_rwd"}) {
		t.Fatalf("unexpected OpenSearch roles: %#v", got)
	}
}

func TestRoleRequestForAccessModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		access            Access
		wantAllowed       []string
		wantTenantAllowed string
	}{
		{name: "read", access: Access{Namespace: "team1", PullOnly: true}, wantAllowed: []string{"read"}, wantTenantAllowed: "kibana_all_write"},
		{name: "read delete", access: Access{Namespace: "team1", PullOnly: true, DeleteAllowed: true}, wantAllowed: []string{"read", "delete"}, wantTenantAllowed: "kibana_all_write"},
		{name: "read write", access: Access{Namespace: "team1", PullOnly: false}, wantAllowed: []string{"read", "write"}, wantTenantAllowed: "kibana_all_write"},
		{name: "read write delete", access: Access{Namespace: "team1", PullOnly: false, DeleteAllowed: true}, wantAllowed: []string{"crud"}, wantTenantAllowed: "kibana_all_write"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := roleRequestForAccess(tt.access)
			if got := role.IndexPermissions[0].AllowedActions; !reflect.DeepEqual(got, tt.wantAllowed) {
				t.Fatalf("unexpected allowed actions: %#v", got)
			}
			if got := role.IndexPermissions[1].IndexPatterns; !reflect.DeepEqual(got, []string{"*"}) {
				t.Fatalf("unexpected resolve index patterns: %#v", got)
			}
			if got := role.IndexPermissions[1].AllowedActions; !reflect.DeepEqual(got, []string{"indices:admin/resolve/index"}) {
				t.Fatalf("unexpected resolve index actions: %#v", got)
			}
			if got := role.TenantPermissions[0].AllowedActions; !reflect.DeepEqual(got, []string{tt.wantTenantAllowed}) {
				t.Fatalf("unexpected tenant actions: %#v", got)
			}
			if !strings.Contains(strings.Join(role.ClusterPermissions, ","), "cluster:admin/opensearch/ql/datasources/read") {
				t.Fatalf("expected datasources cluster permission, got %#v", role.ClusterPermissions)
			}
		})
	}
}

func TestNormalizeAccessByNamespaceCombinesPermissions(t *testing.T) {
	t.Parallel()

	result := normalizeAccessByNamespace([]Access{
		{Group: "team1_rw", Namespace: "team1", PullOnly: false},
		{Group: "team1_rd", Namespace: "team1", PullOnly: true, DeleteAllowed: true},
		{Group: "team2_r", Namespace: "team2", PullOnly: true},
	})

	if len(result) != 2 {
		t.Fatalf("expected two namespaces, got %#v", result)
	}
	if got := roleModeForAccess(result[0]); got != "rwd" {
		t.Fatalf("expected team1 to combine to rwd, got %q", got)
	}
	if got := roleModeForAccess(result[1]); got != "r" {
		t.Fatalf("expected team2 to remain r, got %q", got)
	}
}

func TestGatewayDashboardsRequiresLogin(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(Config{DashboardsURL: "http://dashboards.example"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboards/app/home", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
	}
}

func TestGatewayDashboardsProxyForwardsSessionBasicAuth(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	var upstreamAuth string
	var upstreamPath string
	var upstreamQuery string
	var upstreamTenant string
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		upstreamTenant = r.Header.Get("securitytenant")
		upstreamPath = r.URL.Path
		upstreamQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied dashboards")
	}))
	defer dashboards.Close()

	gateway := newGateway(newClient(testConfigWithDashboards(openSearch, dashboards)), nil)
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "testuser"},
		AuthHeader: buildBasicAuthorization("testuser", "dogood"),
		Namespaces: []string{"team1"},
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboards/app/home?foo=bar", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if upstreamAuth != buildBasicAuthorization("testuser", "dogood") {
		t.Fatalf("unexpected Authorization header: %q", upstreamAuth)
	}
	if upstreamTenant != "team1" {
		t.Fatalf("expected single namespace tenant header, got %q", upstreamTenant)
	}
	if upstreamPath != "/dashboards/app/home" || upstreamQuery != "foo=bar" {
		t.Fatalf("unexpected upstream request: path=%q query=%q", upstreamPath, upstreamQuery)
	}
	if body := recorder.Body.String(); body != "proxied dashboards" {
		t.Fatalf("unexpected proxy body: %q", body)
	}
}

func TestGatewayDashboardsProxyDoesNotAutoSelectTenantForMultiNamespaceSession(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	var upstreamTenant string
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTenant = r.Header.Get("securitytenant")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied dashboards")
	}))
	defer dashboards.Close()

	gateway := newGateway(newClient(testConfigWithDashboards(openSearch, dashboards)), nil)
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "testuser"},
		AuthHeader: buildBasicAuthorization("testuser", "dogood"),
		Namespaces: []string{"team1", "team2"},
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboards/app/home", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if upstreamTenant != "" {
		t.Fatalf("expected no auto-selected tenant for multi-namespace session, got %q", upstreamTenant)
	}
}

func TestGatewayDashboardsProxySynthesizesTenantIndexPatternFindResults(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("securitytenant"); got != "team1" {
			t.Fatalf("expected securitytenant header, got %q", got)
		}
		if r.Method != http.MethodGet || r.URL.Path != "/dashboards/api/saved_objects/_find" {
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"page":1,"per_page":10000,"total":0,"saved_objects":[]}`)
	}))
	defer dashboards.Close()

	gateway := newGateway(newClient(testConfigWithDashboards(openSearch, dashboards)), nil)
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "testuser"},
		AuthHeader: buildBasicAuthorization("testuser", "dogood"),
		Namespaces: []string{"team1"},
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?fields=title&per_page=10000&type=index-pattern", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	var payload dashboardsFindResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode proxy response: %v", err)
	}
	if payload.Total != 1 || len(payload.SavedObjects) != 1 {
		t.Fatalf("expected synthesized saved object, got %#v", payload)
	}
	if got := payload.SavedObjects[0].ID; got != buildDataViewID("team1") {
		t.Fatalf("unexpected data view id: %q", got)
	}
	if got := payload.SavedObjects[0].Attributes.Title; got != "team1-*" {
		t.Fatalf("unexpected data view title: %q", got)
	}
}

func TestGatewayDashboardsProxyLeavesNonEmptyIndexPatternFindResultsUntouched(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	const upstreamBody = `{"page":1,"per_page":10000,"total":1,"saved_objects":[{"id":"upstream-pattern","type":"index-pattern","attributes":{"title":"custom-*","timeFieldName":"event_time"}}]}`
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer dashboards.Close()

	gateway := newGateway(newClient(testConfigWithDashboards(openSearch, dashboards)), nil)
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "testuser"},
		AuthHeader: buildBasicAuthorization("testuser", "dogood"),
		Namespaces: []string{"team1"},
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboards/api/saved_objects/_find?fields=title&per_page=10000&type=index-pattern", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := strings.TrimSpace(recorder.Body.String()); body != upstreamBody {
		t.Fatalf("expected upstream body to pass through, got %s", body)
	}
}

func TestGatewayLogoutClearsSession(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Dashboards request after logout: %s %s", r.Method, r.URL.Path)
	}))
	defer dashboards.Close()

	gateway := newGateway(newClient(testConfigWithDashboards(openSearch, dashboards)), nil)
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "testuser"},
		AuthHeader: buildBasicAuthorization("testuser", "dogood"),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	logoutRecorder := httptest.NewRecorder()
	logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(logoutRecorder, logoutRequest)

	if logoutRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected logout redirect, got %d", logoutRecorder.Code)
	}
	if _, ok := gateway.sessions.Get(token); ok {
		t.Fatal("expected session to be deleted")
	}

	dashboardRecorder := httptest.NewRecorder()
	dashboardRequest := httptest.NewRequest(http.MethodGet, "/dashboards/app/home", nil)
	dashboardRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(dashboardRecorder, dashboardRequest)

	if dashboardRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303 after logout, got %d", dashboardRecorder.Code)
	}
	if got := dashboardRecorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login after logout, got %q", got)
	}
}

func TestGatewayExpiredSessionRedirectsToLogin(t *testing.T) {
	t.Parallel()

	gateway := newGateway(newClient(Config{DashboardsURL: "http://dashboards.example"}), nil)
	gateway.sessions.Set("expired", sessionData{
		User:       &User{Name: "testuser"},
		AuthHeader: buildBasicAuthorization("testuser", "dogood"),
		ExpiresAt:  time.Now().Add(-time.Minute),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboards/app/home", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "expired"})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
	}
}

func TestGatewayIngestRequiresAuthentication(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")

	testGatewayHandler(testConfig(openSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != `Basic realm="OpenSearchGateway ingest"` {
		t.Fatalf("unexpected WWW-Authenticate header: %q", got)
	}
}

func TestGatewayIngestRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("writer", "wrong")

	testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return nil, nil, errLDAPInvalidCredentials
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestRejectsReadOnlyAccess(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("johndoe", "dogood")

	testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return &User{Name: username, Namespace: "team10", PullOnly: true}, []Access{
			{Group: "team10_r", Namespace: "team10", PullOnly: true},
		}, nil
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestRejectsWrongNamespace(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("writer", "secret")

	testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return &User{Name: username, Namespace: "team1"}, []Access{
			{Group: "team1_rw", Namespace: "team1"},
		}, nil
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestUsesAuthenticatedSessionAccess(t *testing.T) {
	t.Parallel()

	var calls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/team10-20241230-rollover":
			w.WriteHeader(http.StatusOK)
		case "POST /team10-20241230-rollover/_doc":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"session-doc"}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	gateway := newGateway(newClient(testConfig(openSearch)), func(username, password string) (*User, []Access, error) {
		t.Fatalf("session-backed ingest should not call LDAP authenticate")
		return nil, nil, nil
	})
	token, expiresAt, err := gateway.sessions.Create(sessionData{
		User:       &User{Name: "ingestuser", Namespace: "team10"},
		Access:     []Access{{Group: "team10_rw", Namespace: "team10"}},
		Namespaces: []string{"team10"},
		AuthHeader: buildBasicAuthorization("ingestuser", "dogood"),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/team10-20241230-rollover",
		"POST /team10-20241230-rollover/_doc",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", calls)
	}
}

func TestGatewayIngestBootstrapsAndIndexes(t *testing.T) {
	t.Parallel()

	var calls []string
	var createBody map[string]any
	var attachBody map[string]any
	var indexBody map[string]any

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-20241230-rollover":
			calls = append(calls, "head")
			w.WriteHeader(http.StatusNotFound)
		case "PUT /orders-20241230-rollover-000001":
			calls = append(calls, "create")
			createBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "POST /_plugins/_ism/add/orders-20241230-rollover-000001":
			calls = append(calls, "attach")
			attachBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "POST /orders-20241230-rollover/_doc":
			calls = append(calls, "index")
			indexBody = decodeRequestBody(t, r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"abc123"}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders/", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello","count":1}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfig(openSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{"head", "create", "attach", "index"}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", calls)
	}

	aliases := nestedMap(t, createBody["aliases"])
	aliasConfig := nestedMap(t, aliases["orders-20241230-rollover"])
	if got := aliasConfig["is_write_index"]; got != true {
		t.Fatalf("expected write alias to be marked as write index, got %#v", got)
	}

	settings := nestedMap(t, createBody["settings"])
	if got := settings["plugins.index_state_management.rollover_alias"]; got != "orders-20241230-rollover" {
		t.Fatalf("unexpected rollover alias setting: %#v", got)
	}

	if got := attachBody["policy_id"]; got != ismPolicyID {
		t.Fatalf("unexpected attached policy id: %#v", got)
	}
	if got := indexBody["event_time"]; got != "2024-12-30T10:11:12Z" {
		t.Fatalf("unexpected normalized event_time: %#v", got)
	}
	if got := indexBody["count"]; got != float64(1) {
		t.Fatalf("expected arbitrary fields to be preserved, got %#v", got)
	}

	var response ingestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result != "created" || response.DocumentID != "abc123" || response.WriteAlias != "orders-20241230-rollover" || !response.Bootstrapped {
		t.Fatalf("unexpected gateway response: %#v", response)
	}
}

func TestGatewayRepeatWriteSkipsBootstrap(t *testing.T) {
	t.Parallel()

	var calls []string

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-20241230-rollover":
			calls = append(calls, "head")
			w.WriteHeader(http.StatusOK)
		case "POST /orders-20241230-rollover/_doc":
			calls = append(calls, "index")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"steady"}`)
		default:
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfig(openSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{"head", "index"}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", calls)
	}

	var response ingestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Bootstrapped {
		t.Fatalf("expected repeat write to skip bootstrap, got %#v", response)
	}
	if response.WriteAlias != "orders-20241230-rollover" {
		t.Fatalf("unexpected alias: %#v", response)
	}
}

func TestGatewayValidationErrors(t *testing.T) {
	t.Parallel()

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected OpenSearch call for validation error case: %s %s", r.Method, r.URL.Path)
	}))
	defer openSearch.Close()

	longIndexName := strings.Repeat("a", 240)
	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "invalid json", method: http.MethodPost, path: "/ingest/orders", contentType: "application/json", body: `{"event_time":`, wantStatus: http.StatusBadRequest},
		{name: "non object body", method: http.MethodPost, path: "/ingest/orders", contentType: "application/json", body: `[]`, wantStatus: http.StatusBadRequest},
		{name: "missing event_time", method: http.MethodPost, path: "/ingest/orders", contentType: "application/json", body: `{"message":"hello"}`, wantStatus: http.StatusBadRequest},
		{name: "non string event_time", method: http.MethodPost, path: "/ingest/orders", contentType: "application/json", body: `{"event_time":123}`, wantStatus: http.StatusBadRequest},
		{name: "non utc event_time", method: http.MethodPost, path: "/ingest/orders", contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12+02:00"}`, wantStatus: http.StatusBadRequest},
		{name: "invalid index", method: http.MethodPost, path: "/ingest/Orders", contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusBadRequest},
		{name: "extra path segments", method: http.MethodPost, path: "/ingest/orders/extra", contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusBadRequest},
		{name: "wrong content type", method: http.MethodPost, path: "/ingest/orders", contentType: "text/plain", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "wrong method", method: http.MethodGet, path: "/ingest/orders", contentType: "application/json", body: ``, wantStatus: http.StatusMethodNotAllowed},
		{name: "name too long", method: http.MethodPost, path: "/ingest/" + longIndexName, contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusBadRequest},
	}

	gateway := testGatewayHandlerWithAuth(testConfig(openSearch), func(username, password string) (*User, []Access, error) {
		return &User{Name: username, Namespace: "orders"}, []Access{
			{Group: "orders_rw", Namespace: "orders"},
			{Group: longIndexName + "_rw", Namespace: longIndexName},
		}, nil
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				request.Header.Set("Content-Type", tt.contentType)
			}
			addTestIngestBasicAuth(request)

			gateway.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, recorder.Code, recorder.Body.String())
			}
			if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("expected JSON error response, got %q", contentType)
			}
		})
	}
}

func TestGatewayOpenSearchFailuresReturnBadGateway(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantCalls []string
	}{
		{
			name: "alias head failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead || r.URL.Path != "/_alias/orders-20241230-rollover" {
					t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
				}
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			wantCalls: []string{"HEAD /_alias/orders-20241230-rollover"},
		},
		{
			name: "bootstrap put failure",
			handler: sequenceHandler(t,
				responseSpec{method: http.MethodHead, path: "/_alias/orders-20241230-rollover", status: http.StatusNotFound},
				responseSpec{method: http.MethodPut, path: "/orders-20241230-rollover-000001", status: http.StatusInternalServerError, body: `{"error":"create failed"}`},
			),
			wantCalls: []string{
				"HEAD /_alias/orders-20241230-rollover",
				"PUT /orders-20241230-rollover-000001",
			},
		},
		{
			name: "document post failure",
			handler: sequenceHandler(t,
				responseSpec{method: http.MethodHead, path: "/_alias/orders-20241230-rollover", status: http.StatusOK},
				responseSpec{method: http.MethodPost, path: "/orders-20241230-rollover/_doc", status: http.StatusInternalServerError, body: `{"error":"index failed"}`},
			),
			wantCalls: []string{
				"HEAD /_alias/orders-20241230-rollover",
				"POST /orders-20241230-rollover/_doc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				tt.handler.ServeHTTP(w, r)
			}))
			defer openSearch.Close()

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
			request.Header.Set("Content-Type", "application/json")
			addTestIngestBasicAuth(request)

			testGatewayHandler(testConfig(openSearch)).ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Fatalf("unexpected OpenSearch sequence: %#v", calls)
			}
		})
	}
}

func TestGatewayTenantFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()

	var openSearchCalls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"tenant lookup failed"}`, http.StatusInternalServerError)
	}))
	defer openSearch.Close()

	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
	}))
	defer dashboards.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfigWithDashboards(openSearch, dashboards)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(openSearchCalls, []string{
		"GET /_plugins/_security/api/tenants/orders",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", openSearchCalls)
	}
}

func TestGatewayDataViewFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()

	var openSearchCalls []string
	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openSearchCalls = append(openSearchCalls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_plugins/_security/api/tenants/orders" {
			t.Fatalf("unexpected OpenSearch request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"orders":{"reserved":false}}`)
	}))
	defer openSearch.Close()

	var dashboardsCalls []string
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dashboardsCalls = append(dashboardsCalls, r.Method+" "+r.URL.RequestURI())

		if r.Method != http.MethodPost || r.URL.RequestURI() != "/dashboards/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true" {
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
		}
		http.Error(w, `{"error":"data view create failed"}`, http.StatusInternalServerError)
	}))
	defer dashboards.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfigWithDashboards(openSearch, dashboards)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(openSearchCalls, []string{
		"GET /_plugins/_security/api/tenants/orders",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", openSearchCalls)
	}
	if !reflect.DeepEqual(dashboardsCalls, []string{
		"POST /dashboards/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true",
	}) {
		t.Fatalf("unexpected Dashboards sequence: %#v", dashboardsCalls)
	}
}

func TestGatewayBootstrapConflictRetriesAliasCheck(t *testing.T) {
	t.Parallel()

	var calls []string

	openSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch len(calls) {
		case 1:
			if r.Method != http.MethodHead || r.URL.Path != "/_alias/orders-20241230-rollover" {
				t.Fatalf("unexpected first request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNotFound)
		case 2:
			if r.Method != http.MethodPut || r.URL.Path != "/orders-20241230-rollover-000001" {
				t.Fatalf("unexpected second request: %s %s", r.Method, r.URL.Path)
			}
			http.Error(w, `{"error":{"type":"resource_already_exists_exception"}}`, http.StatusConflict)
		case 3:
			if r.Method != http.MethodHead || r.URL.Path != "/_alias/orders-20241230-rollover" {
				t.Fatalf("unexpected third request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		case 4:
			if r.Method != http.MethodPost || r.URL.Path != "/orders-20241230-rollover/_doc" {
				t.Fatalf("unexpected fourth request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"after-race"}`)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer openSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfig(openSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/orders-20241230-rollover",
		"PUT /orders-20241230-rollover-000001",
		"HEAD /_alias/orders-20241230-rollover",
		"POST /orders-20241230-rollover/_doc",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", calls)
	}

	var response ingestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Bootstrapped {
		t.Fatalf("expected race winner to be another writer, got %#v", response)
	}
	if response.DocumentID != "after-race" {
		t.Fatalf("unexpected response after conflict retry: %#v", response)
	}
}

type responseSpec struct {
	method string
	path   string
	status int
	body   string
}

func sequenceHandler(t *testing.T, responses ...responseSpec) http.HandlerFunc {
	t.Helper()

	var index int
	return func(w http.ResponseWriter, r *http.Request) {
		if index >= len(responses) {
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}

		response := responses[index]
		index++

		if r.Method != response.method || r.URL.Path != response.path {
			t.Fatalf("unexpected request %d: got %s %s, want %s %s", index, r.Method, r.URL.Path, response.method, response.path)
		}
		w.WriteHeader(response.status)
		if response.body != "" {
			_, _ = io.WriteString(w, response.body)
		}
	}
}

func testConfig(server *httptest.Server) Config {
	return Config{
		BaseURL:            server.URL,
		Username:           "admin",
		Password:           "Admin123!",
		DashboardsUsername: "admin",
		DashboardsPassword: "Admin123!",
		DashboardsTenant:   "admin_tenant",
		ListenAddr:         ":0",
		Shards:             2,
		Replicas:           2,
		HTTPClient:         server.Client(),
	}
}

func testConfigWithDashboards(openSearch, dashboards *httptest.Server) Config {
	cfg := testConfig(openSearch)
	cfg.DashboardsURL = dashboards.URL
	cfg.HTTPClient = openSearch.Client()
	return cfg
}

func testGatewayHandler(cfg Config) http.Handler {
	return testGatewayHandlerWithAuth(cfg, defaultTestLDAPAuthenticator)
}

func testGatewayHandlerWithAuth(cfg Config, authenticate ldapAuthenticator) http.Handler {
	return newGateway(newClient(cfg), authenticate).Handler()
}

func defaultTestLDAPAuthenticator(username, password string) (*User, []Access, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, nil, errLDAPInvalidCredentials
	}

	return &User{Name: username, Namespace: "orders"}, []Access{
		{Group: "orders_rw", Namespace: "orders"},
		{Group: "team1_rw", Namespace: "team1"},
		{Group: "team10_rw", Namespace: "team10"},
	}, nil
}

func addTestIngestBasicAuth(request *http.Request) {
	request.SetBasicAuth("writer", "secret")
}

func decodeRequestBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()

	if r.Body == nil {
		return nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode request body %q: %v", string(body), err)
	}
	return payload
}

func nestedMap(t *testing.T, value any) map[string]any {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %#v", value)
	}
	return object
}

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

	client := &Client{cfg: testConfig(openSearch)}
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

	client := &Client{cfg: testConfig(openSearch)}
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

	client := &Client{cfg: cfg}
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

	client := &Client{cfg: cfg}
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

	client := &Client{cfg: cfg}
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
	dashboards := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true"
		if r.Method != http.MethodPost || r.URL.RequestURI() != expectedPath {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.Header.Get("osd-xsrf"); got != "true" {
			t.Fatalf("expected osd-xsrf header, got %q", got)
		}
		if got := r.Header.Get("securitytenant"); got != "orders" {
			t.Fatalf("expected securitytenant header, got %q", got)
		}

		requestBody = decodeRequestBody(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer dashboards.Close()

	client := &Client{cfg: testConfigWithDashboards(openSearch, dashboards)}

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
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true" {
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.Header.Get("securitytenant"); got != "orders" {
			t.Fatalf("expected securitytenant header, got %q", got)
		}
		appendCall("data-view-post")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer dashboards.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")

	(&Gateway{client: &Client{cfg: testConfigWithDashboards(openSearch, dashboards)}}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"tenant-get",
		"data-view-post",
		"alias-head",
		"doc-post",
	}) {
		t.Fatalf("unexpected request order: %#v", calls)
	}
}

func TestGatewayRootServesDemoForm(t *testing.T) {
	t.Parallel()

	gateway := &Gateway{client: &Client{cfg: Config{}}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

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
	if !strings.Contains(body, "/ingest/") {
		t.Fatalf("expected demo page to reference ingest endpoint, got %q", body)
	}
}

func TestGatewayRootRejectsNonGet(t *testing.T) {
	t.Parallel()

	gateway := &Gateway{client: &Client{cfg: Config{}}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("expected Allow header %q, got %q", http.MethodGet, got)
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

	(&Gateway{client: &Client{cfg: testConfig(openSearch)}}).ServeHTTP(recorder, request)

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

	(&Gateway{client: &Client{cfg: testConfig(openSearch)}}).ServeHTTP(recorder, request)

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

	gateway := &Gateway{client: &Client{cfg: testConfig(openSearch)}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				request.Header.Set("Content-Type", tt.contentType)
			}

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

			(&Gateway{client: &Client{cfg: testConfig(openSearch)}}).ServeHTTP(recorder, request)

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

	(&Gateway{client: &Client{cfg: testConfigWithDashboards(openSearch, dashboards)}}).ServeHTTP(recorder, request)

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

		if r.Method != http.MethodPost || r.URL.RequestURI() != "/api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true" {
			t.Fatalf("unexpected Dashboards request: %s %s", r.Method, r.URL.RequestURI())
		}
		http.Error(w, `{"error":"data view create failed"}`, http.StatusInternalServerError)
	}))
	defer dashboards.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")

	(&Gateway{client: &Client{cfg: testConfigWithDashboards(openSearch, dashboards)}}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(openSearchCalls, []string{
		"GET /_plugins/_security/api/tenants/orders",
	}) {
		t.Fatalf("unexpected OpenSearch sequence: %#v", openSearchCalls)
	}
	if !reflect.DeepEqual(dashboardsCalls, []string{
		"POST /api/saved_objects/index-pattern/gateway-index-pattern-orders?overwrite=true",
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

	(&Gateway{client: &Client{cfg: testConfig(openSearch)}}).ServeHTTP(recorder, request)

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

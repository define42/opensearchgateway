package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/define42/opensearchgateway/internal/opensearch"
	"github.com/define42/opensearchgateway/internal/session"
)

func (g *Gateway) proxyDashboards(w http.ResponseWriter, r *http.Request, sessionData session.Data) error {
	target, err := url.Parse(g.Client.Config.DashboardsURL)
	if err != nil {
		return fmt.Errorf("invalid Dashboards URL: %w", err)
	}

	defaultTenant := sessionDefaultTenant(sessionData)
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		originalDirector(req)
		req.Host = target.Host
		req.Header.Del("Authorization")
		req.Header.Set("Authorization", sessionData.AuthHeader)
		if req.Header.Get("securitytenant") == "" && defaultTenant != "" {
			req.Header.Set("securitytenant", defaultTenant)
		}
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", ForwardedProto(r))
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		return g.ModifyDashboardsResponse(resp, sessionData)
	}
	proxy.ErrorHandler = func(proxyWriter http.ResponseWriter, proxyRequest *http.Request, proxyErr error) {
		writeErrorJSON(proxyWriter, http.StatusBadGateway, fmt.Sprintf("Dashboards proxy failed: %v", proxyErr))
	}

	proxy.ServeHTTP(w, r)
	return nil
}

func (g *Gateway) ModifyDashboardsResponse(resp *http.Response, sessionData session.Data) error {
	if resp == nil || resp.Request == nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK || resp.Request.Method != http.MethodGet {
		return nil
	}
	if !IsDashboardsIndexPatternFindRequest(resp.Request) {
		return nil
	}

	tenantName := strings.TrimSpace(resp.Request.Header.Get("securitytenant"))
	if tenantName == "" {
		tenantName = sessionDefaultTenant(sessionData)
	}
	if tenantName == "" || !SessionHasNamespace(sessionData, tenantName) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	restoreBody := func(payload []byte) {
		resp.Body = io.NopCloser(bytes.NewReader(payload))
		resp.ContentLength = int64(len(payload))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	}

	var payload opensearch.DashboardsFindResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		restoreBody(body)
		return nil
	}
	if payload.Total != 0 || !MatchesIndexPatternFindQuery(resp.Request.URL.Query(), tenantName) {
		restoreBody(body)
		return nil
	}

	synthetic := opensearch.DashboardsFindResponse{
		Page:    payload.Page,
		PerPage: payload.PerPage,
		Total:   1,
		SavedObjects: []opensearch.DashboardsSavedObjectResponse{
			{
				ID:   opensearch.BuildDataViewID(tenantName),
				Type: "index-pattern",
				Attributes: opensearch.DashboardsDataViewAttributes{
					Title:         opensearch.BuildDataViewPattern(tenantName),
					TimeFieldName: "event_time",
				},
				References: []any{},
			},
		},
	}
	if payload.Page > 1 || payload.PerPage == 0 {
		synthetic.SavedObjects = []opensearch.DashboardsSavedObjectResponse{}
	}

	replacement, err := json.Marshal(synthetic)
	if err != nil {
		return err
	}
	restoreBody(replacement)
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	return nil
}

func IsDashboardsIndexPatternFindRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if req.URL.Path != opensearch.DashboardsAPIPath("/api/saved_objects/_find") {
		return false
	}

	for _, item := range req.URL.Query()["type"] {
		if item == "index-pattern" {
			return true
		}
	}
	return false
}

func MatchesIndexPatternFindQuery(values url.Values, tenantName string) bool {
	search := strings.TrimSpace(strings.Trim(values.Get("search"), "*"))
	if search == "" {
		return true
	}

	title := opensearch.BuildDataViewPattern(tenantName)
	id := opensearch.BuildDataViewID(tenantName)
	return strings.Contains(title, search) || strings.Contains(id, search) || strings.Contains(tenantName, search)
}

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

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", ForwardedProto(pr.In))
		},
		ModifyResponse: func(resp *http.Response) error {
			return g.ModifyDashboardsResponse(resp, sessionData)
		},
		ErrorHandler: func(proxyWriter http.ResponseWriter, _ *http.Request, proxyErr error) {
			writeErrorJSON(proxyWriter, http.StatusBadGateway, fmt.Sprintf("Dashboards proxy failed: %v", proxyErr))
		},
	}

	proxy.ServeHTTP(w, r)
	return nil
}

// ModifyDashboardsResponse patches tenant-scoped data-view lookup responses.
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

	tenantName, ok := dashboardsTenantName(resp.Request, sessionData)
	if !ok {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	var payload opensearch.DashboardsFindResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		restoreDashboardsBody(resp, body)
		return nil
	}
	replacementPayload, changed := g.enrichIndexPatternFindResponse(payload, resp.Request, tenantName)
	if !changed {
		restoreDashboardsBody(resp, body)
		return nil
	}

	replacement, err := json.Marshal(replacementPayload)
	if err != nil {
		return err
	}
	restoreDashboardsBody(resp, replacement)
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	return nil
}

func dashboardsTenantName(req *http.Request, sessionData session.Data) (string, bool) {
	if req == nil || req.URL == nil {
		return "", false
	}

	candidates := []string{
		req.Header.Get("securitytenant"),
		req.URL.Query().Get("security_tenant"),
		req.URL.Query().Get("securitytenant"),
	}
	for _, candidate := range candidates {
		tenantName := strings.TrimSpace(candidate)
		if tenantName != "" && SessionHasNamespace(sessionData, tenantName) {
			return tenantName, true
		}
	}
	return "", false
}

func restoreDashboardsBody(resp *http.Response, payload []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(payload))
	resp.ContentLength = int64(len(payload))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
}

func (g *Gateway) enrichIndexPatternFindResponse(payload opensearch.DashboardsFindResponse, req *http.Request, tenantName string) (opensearch.DashboardsFindResponse, bool) {
	query := req.URL.Query()
	candidates := make([]opensearch.DashboardsSavedObjectResponse, 0)
	if payload.Total == 0 && MatchesIndexPatternFindQuery(query, tenantName) {
		candidates = append(candidates, opensearch.BuildDataViewSavedObject(tenantName))
	}
	for _, object := range g.Client.EnsuredDashboardDataViews(tenantName) {
		if MatchesDataViewFindQuery(query, object) {
			candidates = append(candidates, object)
		}
	}
	if len(candidates) == 0 {
		return payload, false
	}

	seen := make(map[string]struct{}, len(payload.SavedObjects)+len(candidates))
	for _, object := range payload.SavedObjects {
		seen[object.ID] = struct{}{}
	}

	missing := make([]opensearch.DashboardsSavedObjectResponse, 0, len(candidates))
	for _, object := range candidates {
		if _, ok := seen[object.ID]; ok {
			continue
		}
		seen[object.ID] = struct{}{}
		missing = append(missing, object)
	}
	if len(missing) == 0 {
		return payload, false
	}

	payload.Total += len(missing)
	if payload.Page <= 1 && payload.PerPage > 0 {
		available := payload.PerPage - len(payload.SavedObjects)
		if available > len(missing) {
			available = len(missing)
		}
		if available > 0 {
			payload.SavedObjects = append(payload.SavedObjects, missing[:available]...)
		}
	}
	return payload, true
}

// IsDashboardsIndexPatternFindRequest reports whether req is a data-view search.
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

// MatchesIndexPatternFindQuery reports whether values target tenantName's data view.
func MatchesIndexPatternFindQuery(values url.Values, tenantName string) bool {
	search := strings.TrimSpace(strings.Trim(values.Get("search"), "*"))
	if search == "" {
		return true
	}

	title := opensearch.BuildDataViewPattern(tenantName)
	id := opensearch.BuildDataViewID(tenantName)
	return strings.Contains(title, search) || strings.Contains(id, search) || strings.Contains(tenantName, search)
}

// MatchesDataViewFindQuery reports whether values target object.
func MatchesDataViewFindQuery(values url.Values, object opensearch.DashboardsSavedObjectResponse) bool {
	search := strings.TrimSpace(strings.Trim(values.Get("search"), "*"))
	if search == "" {
		return true
	}

	return strings.Contains(object.Attributes.Title, search) || strings.Contains(object.ID, search)
}

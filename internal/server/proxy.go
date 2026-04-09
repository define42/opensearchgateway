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
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			if pr.Out.Header.Get("securitytenant") == "" && defaultTenant != "" {
				pr.Out.Header.Set("securitytenant", defaultTenant)
			}
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
	if !shouldPatchIndexPatternResponse(payload, resp.Request, tenantName) {
		restoreDashboardsBody(resp, body)
		return nil
	}

	replacement, err := json.Marshal(syntheticIndexPatternFindResponse(payload, tenantName))
	if err != nil {
		return err
	}
	restoreDashboardsBody(resp, replacement)
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	return nil
}

func dashboardsTenantName(req *http.Request, sessionData session.Data) (string, bool) {
	tenantName := strings.TrimSpace(req.Header.Get("securitytenant"))
	if tenantName == "" {
		tenantName = sessionDefaultTenant(sessionData)
	}
	if tenantName == "" || !SessionHasNamespace(sessionData, tenantName) {
		return "", false
	}
	return tenantName, true
}

func shouldPatchIndexPatternResponse(payload opensearch.DashboardsFindResponse, req *http.Request, tenantName string) bool {
	return payload.Total == 0 && MatchesIndexPatternFindQuery(req.URL.Query(), tenantName)
}

func restoreDashboardsBody(resp *http.Response, payload []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(payload))
	resp.ContentLength = int64(len(payload))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
}

func syntheticIndexPatternFindResponse(payload opensearch.DashboardsFindResponse, tenantName string) opensearch.DashboardsFindResponse {
	response := opensearch.DashboardsFindResponse{
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
		response.SavedObjects = []opensearch.DashboardsSavedObjectResponse{}
	}
	return response
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

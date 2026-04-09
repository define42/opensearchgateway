package opensearch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) EnsureTenant(ctx context.Context, tenantName string) error {
	if c.Config.DashboardsURL == "" {
		return nil
	}

	if _, ok := c.EnsuredTenants.Load(tenantName); ok {
		return nil
	}

	path := "/_plugins/_security/api/tenants/" + url.PathEscape(tenantName)
	err := c.DoJSON(ctx, http.MethodGet, path, nil, nil, []int{http.StatusOK})
	if err != nil {
		if !IsNotFoundResponse(err) {
			return err
		}

		body := TenantRequest{
			Description: fmt.Sprintf("Gateway tenant for %s", tenantName),
		}
		if err := c.DoJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
			return err
		}
	}

	c.EnsuredTenants.Store(tenantName, true)
	return nil
}

func (c *Client) EnsureDashboardDataView(ctx context.Context, indexName string) error {
	if c.Config.DashboardsURL == "" {
		return nil
	}

	if err := c.EnsureTenant(ctx, indexName); err != nil {
		return err
	}

	tenantName := indexName
	dataViewID := BuildDataViewID(indexName)
	cacheKey := tenantName + "/" + dataViewID
	if _, ok := c.EnsuredDataViews.Load(cacheKey); ok {
		return nil
	}

	body := DashboardsSavedObjectRequest{
		Attributes: DashboardsDataViewAttributes{
			Title:         BuildDataViewPattern(indexName),
			TimeFieldName: "event_time",
		},
	}

	path := "/api/saved_objects/index-pattern/" + url.PathEscape(dataViewID) + "?overwrite=true"
	if err := c.DoDashboardsJSONInTenant(ctx, tenantName, http.MethodPost, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return err
	}
	if err := c.SetDashboardsDefaultIndex(ctx, tenantName, dataViewID); err != nil {
		return err
	}

	c.EnsuredDataViews.Store(cacheKey, true)
	return nil
}

func (c *Client) SetDashboardsDefaultIndex(ctx context.Context, tenantName, dataViewID string) error {
	body := DashboardsSettingValueRequest{
		Value: dataViewID,
	}
	if err := c.DoDashboardsJSONInTenant(ctx, tenantName, http.MethodPost, "/api/opensearch-dashboards/settings/defaultIndex", body, nil, []int{http.StatusOK}); err != nil {
		return fmt.Errorf("set Dashboards default index for tenant %q: %w", tenantName, err)
	}
	return nil
}

func BuildDataViewID(indexName string) string {
	return "gateway-index-pattern-" + indexName
}

func BuildDataViewPattern(indexName string) string {
	return indexName + "-*"
}

func DashboardsAPIPath(path string) string {
	if path == "/dashboards" || strings.HasPrefix(path, "/dashboards/") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return "/dashboards" + path
	}
	return "/dashboards/" + path
}

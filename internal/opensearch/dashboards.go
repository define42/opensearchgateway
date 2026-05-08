package opensearch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// EnsureTenant creates tenantName if it does not already exist.
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

// EnsureDashboardDataView ensures indexName's data view inside tenantName.
func (c *Client) EnsureDashboardDataView(ctx context.Context, tenantName, indexName string) error {
	if c.Config.DashboardsURL == "" {
		return nil
	}

	if err := c.EnsureTenant(ctx, tenantName); err != nil {
		return err
	}

	dataViewID := BuildDataViewID(indexName)
	cacheKey := BuildDataViewCacheKey(tenantName, indexName)
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
	if err := c.ensureDashboardsDefaultIndex(ctx, tenantName, indexName, dataViewID); err != nil {
		return err
	}

	c.EnsuredDataViews.Store(cacheKey, indexName)
	return nil
}

func (c *Client) ensureDashboardsDefaultIndex(ctx context.Context, tenantName, indexName, dataViewID string) error {
	if tenantName == indexName {
		return c.SetDashboardsDefaultIndex(ctx, tenantName, dataViewID)
	}
	return c.SetDashboardsDefaultIndexIfMissing(ctx, tenantName, dataViewID)
}

// SetDashboardsDefaultIndexIfMissing sets the tenant default only when no default exists.
func (c *Client) SetDashboardsDefaultIndexIfMissing(ctx context.Context, tenantName, dataViewID string) error {
	if _, ok, err := c.DashboardsDefaultIndex(ctx, tenantName); err != nil {
		return err
	} else if ok {
		return nil
	}
	return c.SetDashboardsDefaultIndex(ctx, tenantName, dataViewID)
}

// DashboardsDefaultIndex returns the current tenant default data-view id, if set.
func (c *Client) DashboardsDefaultIndex(ctx context.Context, tenantName string) (string, bool, error) {
	var response DashboardsSettingsResponse
	err := c.DoDashboardsJSONInTenant(ctx, tenantName, http.MethodGet, "/api/opensearch-dashboards/settings/defaultIndex", nil, &response, []int{http.StatusOK})
	if err != nil {
		if IsNotFoundResponse(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get Dashboards default index for tenant %q: %w", tenantName, err)
	}

	setting, ok := response.Settings["defaultIndex"]
	if !ok {
		return "", false, nil
	}
	if value := dashboardsSettingString(setting.UserValue); value != "" {
		return value, true, nil
	}
	if value := dashboardsSettingString(setting.Value); value != "" {
		return value, true, nil
	}
	return "", false, nil
}

// SetDashboardsDefaultIndex sets the default data view inside tenantName.
func (c *Client) SetDashboardsDefaultIndex(ctx context.Context, tenantName, dataViewID string) error {
	body := DashboardsSettingValueRequest{
		Value: dataViewID,
	}
	if err := c.DoDashboardsJSONInTenant(ctx, tenantName, http.MethodPost, "/api/opensearch-dashboards/settings/defaultIndex", body, nil, []int{http.StatusOK}); err != nil {
		return fmt.Errorf("set Dashboards default index for tenant %q: %w", tenantName, err)
	}
	return nil
}

// BuildDataViewID returns the deterministic Dashboards data-view id for indexName.
func BuildDataViewID(indexName string) string {
	return "gateway-index-pattern-" + indexName
}

// BuildDataViewCacheKey returns the tenant-scoped cache key for indexName.
func BuildDataViewCacheKey(tenantName, indexName string) string {
	return tenantName + "/" + BuildDataViewID(indexName)
}

// BuildDataViewPattern returns the wildcard pattern used by a tenant data view.
func BuildDataViewPattern(indexName string) string {
	return indexName + "-*"
}

// DashboardsAPIPath ensures path is rooted under the Dashboards base path.
func DashboardsAPIPath(path string) string {
	if path == "/dashboards" || strings.HasPrefix(path, "/dashboards/") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return "/dashboards" + path
	}
	return "/dashboards/" + path
}

func dashboardsSettingString(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

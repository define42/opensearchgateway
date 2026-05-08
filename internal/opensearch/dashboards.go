package opensearch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
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
	if err := c.SetDashboardsDefaultIndex(ctx, tenantName, dataViewID); err != nil {
		return err
	}

	c.EnsuredDataViews.Store(cacheKey, indexName)
	return nil
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

// IndexNameFromDataViewID extracts the gateway index name from dataViewID.
func IndexNameFromDataViewID(dataViewID string) (string, bool) {
	indexName := strings.TrimPrefix(dataViewID, "gateway-index-pattern-")
	if indexName == dataViewID || indexName == "" {
		return "", false
	}
	return indexName, true
}

// BuildDataViewSavedObject returns the saved-object representation for indexName.
func BuildDataViewSavedObject(indexName string) DashboardsSavedObjectResponse {
	return DashboardsSavedObjectResponse{
		ID:   BuildDataViewID(indexName),
		Type: "index-pattern",
		Attributes: DashboardsDataViewAttributes{
			Title:         BuildDataViewPattern(indexName),
			TimeFieldName: "event_time",
		},
		References: []any{},
	}
}

// EnsuredDashboardDataViews returns data views known to exist in tenantName.
func (c *Client) EnsuredDashboardDataViews(tenantName string) []DashboardsSavedObjectResponse {
	if c == nil {
		return nil
	}

	prefix := tenantName + "/"
	var objects []DashboardsSavedObjectResponse
	c.EnsuredDataViews.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok || !strings.HasPrefix(cacheKey, prefix) {
			return true
		}

		dataViewID := strings.TrimPrefix(cacheKey, prefix)
		indexName, ok := IndexNameFromDataViewID(dataViewID)
		if !ok {
			return true
		}
		if cachedIndexName, ok := value.(string); ok && cachedIndexName != "" {
			indexName = cachedIndexName
		}

		objects = append(objects, BuildDataViewSavedObject(indexName))
		return true
	})

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].ID < objects[j].ID
	})
	return objects
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

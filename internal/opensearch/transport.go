package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func (c *Client) DoJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, c.NewRequest)
}

func (c *Client) DoDashboardsJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, c.NewDashboardsRequest)
}

func (c *Client) DoDashboardsJSONInTenant(ctx context.Context, tenantName, method, path string, body any, out any, okStatuses []int) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, func(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
		return c.NewDashboardsRequestForTenant(ctx, tenantName, method, path, body)
	})
}

func (c *Client) DoJSONWithRequest(ctx context.Context, method, path string, body any, out any, okStatuses []int, buildRequest func(context.Context, string, string, io.Reader) (*http.Request, error)) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}

	req, err := buildRequest(ctx, method, path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.Config.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if !containsStatus(okStatuses, resp.StatusCode) {
		b, _ := io.ReadAll(resp.Body)
		return &ResponseError{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.NewRequestForBase(ctx, c.Config.BaseURL, method, path, body, c.Config.Username, c.Config.Password, nil)
}

func (c *Client) NewDashboardsRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.NewDashboardsRequestForTenant(ctx, c.Config.DashboardsTenant, method, path, body)
}

func (c *Client) NewDashboardsRequestForTenant(ctx context.Context, tenantName, method, path string, body io.Reader) (*http.Request, error) {
	headers := map[string]string{
		"osd-xsrf": "true",
	}
	if tenantName != "" {
		headers["securitytenant"] = tenantName
	}

	return c.NewRequestForBase(ctx, c.Config.DashboardsURL, method, DashboardsAPIPath(path), body, c.Config.DashboardsUsername, c.Config.DashboardsPassword, headers)
}

func (c *Client) NewRequestForBase(ctx context.Context, baseURL, method, path string, body io.Reader, username, password string, headers map[string]string) (*http.Request, error) {
	base := strings.TrimRight(baseURL, "/")
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, err
	}

	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

func containsStatus(ok []int, code int) bool {
	for _, s := range ok {
		if s == code {
			return true
		}
	}
	return false
}

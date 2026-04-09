package opensearch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/define42/opensearchgateway/internal/ingest"
)

func (c *Client) EnsureWriteAlias(ctx context.Context, alias string) (bool, error) {
	exists, err := c.AliasExists(ctx, alias)
	if err != nil {
		return false, fmt.Errorf("check alias %q: %w", alias, err)
	}
	if exists {
		return false, nil
	}

	firstIndex := ingest.BuildFirstBackingIndex(alias)
	if err := c.BootstrapDateStream(ctx, firstIndex, alias); err != nil {
		if IsRetryableBootstrapConflict(err) {
			exists, recheckErr := c.AliasExists(ctx, alias)
			if recheckErr != nil {
				return false, fmt.Errorf("re-check alias %q after bootstrap conflict: %w", alias, recheckErr)
			}
			if exists {
				return false, nil
			}
		}
		return false, fmt.Errorf("bootstrap %q: %w", alias, err)
	}

	if err := c.AttachISMPolicy(ctx, firstIndex, DefaultISMPolicyID); err != nil {
		return false, fmt.Errorf("attach ISM policy to %q: %w", firstIndex, err)
	}

	return true, nil
}

func (c *Client) IndexDocument(ctx context.Context, alias string, document map[string]any) (IndexDocumentResponse, error) {
	path := "/" + url.PathEscape(alias) + "/_doc"

	var response IndexDocumentResponse
	if err := c.DoJSON(ctx, http.MethodPost, path, document, &response, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return IndexDocumentResponse{}, err
	}
	return response, nil
}

func (c *Client) BootstrapDateStream(ctx context.Context, indexName, alias string) error {
	body := map[string]any{
		"aliases": map[string]any{
			alias: map[string]any{
				"is_write_index": true,
			},
		},
		"settings": map[string]any{
			"plugins.index_state_management.rollover_alias": alias,
		},
	}

	return c.DoJSON(ctx, http.MethodPut, "/"+url.PathEscape(indexName), body, nil, []int{http.StatusOK, http.StatusCreated})
}

func (c *Client) AttachISMPolicy(ctx context.Context, indexName, policyID string) error {
	body := map[string]any{
		"policy_id": policyID,
	}

	path := "/_plugins/_ism/add/" + url.PathEscape(indexName)
	return c.DoJSON(ctx, http.MethodPost, path, body, nil, []int{http.StatusOK, http.StatusCreated})
}

func (c *Client) AliasExists(ctx context.Context, alias string) (bool, error) {
	path := "/_alias/" + url.PathEscape(alias)
	req, err := c.NewRequest(ctx, http.MethodHead, path, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.Config.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		b, _ := io.ReadAll(resp.Body)
		return false, &ResponseError{
			Method:     http.MethodHead,
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}
}

func IsRetryableBootstrapConflict(err error) bool {
	var responseErr *ResponseError
	if !errors.As(err, &responseErr) {
		return false
	}
	if responseErr.StatusCode != http.StatusBadRequest && responseErr.StatusCode != http.StatusConflict {
		return false
	}

	body := responseErr.Body
	return strings.Contains(body, "resource_already_exists_exception") || strings.Contains(body, "already exists")
}

func IsNotFoundResponse(err error) bool {
	var responseErr *ResponseError
	return errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound
}

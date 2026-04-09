package opensearch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
)

func (c *Client) EnsureISMPolicy(ctx context.Context, policyID string, minDocCount int) error {
	path := "/_plugins/_ism/policies/" + url.PathEscape(policyID)
	desired := ISMPolicyRequest{
		Policy: BuildISMPolicy(minDocCount),
	}

	var existing ISMPolicyResponse
	err := c.DoJSON(ctx, http.MethodGet, path, nil, &existing, []int{http.StatusOK})
	if err != nil {
		if IsNotFoundResponse(err) {
			return c.DoJSON(ctx, http.MethodPut, path, desired, nil, []int{http.StatusOK, http.StatusCreated})
		}
		return err
	}

	if reflect.DeepEqual(existing.Policy, desired.Policy) {
		return nil
	}

	updatePath := fmt.Sprintf("%s?if_seq_no=%d&if_primary_term=%d", path, existing.SeqNo, existing.PrimaryTerm)
	return c.DoJSON(ctx, http.MethodPut, updatePath, desired, nil, []int{http.StatusOK, http.StatusCreated})
}

func (c *Client) EnsureIndexTemplate(ctx context.Context, templateName string) error {
	body := map[string]any{
		"index_patterns": []string{"*-*-rollover-*"},
		"priority":       100,
		"template": map[string]any{
			"settings": map[string]any{
				"index.number_of_shards":   c.Config.Shards,
				"index.number_of_replicas": c.Config.Replicas,
			},
			"mappings": map[string]any{
				"properties": map[string]any{
					"event_time": map[string]any{
						"type": "date",
					},
				},
			},
		},
	}

	return c.DoJSON(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(templateName), body, nil, []int{http.StatusOK, http.StatusCreated})
}

func BuildISMPolicy(minDocCount int) ISMPolicy {
	return ISMPolicy{
		Description:  "Generic rollover at 100M docs",
		DefaultState: "hot",
		States: []ISMState{
			{
				Name: "hot",
				Actions: []ISMAction{
					{
						Rollover: &ISMRolloverAction{
							MinDocCount: minDocCount,
						},
					},
				},
				Transitions: []ISMTransition{},
			},
		},
	}
}

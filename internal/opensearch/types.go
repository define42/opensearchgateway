// Package opensearch contains the gateway's OpenSearch and Dashboards clients.
package opensearch

import (
	"errors"
	"fmt"
	"sync"

	"github.com/define42/opensearchgateway/internal/config"
)

const (
	// DefaultISMPolicyID is the gateway-managed rollover policy identifier.
	DefaultISMPolicyID = "generic-rollover-100m"
	// DefaultIndexTemplateName is the shared rollover template name.
	DefaultIndexTemplateName = "gateway-rollover-template"
)

// ErrReservedInternalUser reports an internal user that cannot be overwritten.
var ErrReservedInternalUser = errors.New("opensearch internal user is reserved or hidden")

// Client wraps OpenSearch and Dashboards HTTP interactions for the gateway.
type Client struct {
	Config           config.Config
	EnsuredTenants   sync.Map
	EnsuredDataViews sync.Map
}

// ResponseError reports a non-success HTTP response from an upstream API.
type ResponseError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

// Error formats the upstream failure response.
func (e *ResponseError) Error() string {
	return fmt.Sprintf("%s %s failed: status=%d body=%s", e.Method, e.Path, e.StatusCode, e.Body)
}

// IngestResponse is the gateway-facing response after a successful index write.
type IngestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

// IndexDocumentResponse captures the OpenSearch index API response fields used by the gateway.
type IndexDocumentResponse struct {
	ID     string `json:"_id"`
	Result string `json:"result"`
}

// DashboardsSavedObjectRequest creates or updates a Dashboards saved object.
type DashboardsSavedObjectRequest struct {
	Attributes DashboardsDataViewAttributes `json:"attributes"`
}

// DashboardsDataViewAttributes holds the saved object fields for a data view.
type DashboardsDataViewAttributes struct {
	Title         string `json:"title"`
	TimeFieldName string `json:"timeFieldName"`
}

// DashboardsSavedObjectResponse is the saved object representation returned by Dashboards.
type DashboardsSavedObjectResponse struct {
	ID         string                       `json:"id"`
	Type       string                       `json:"type"`
	Attributes DashboardsDataViewAttributes `json:"attributes"`
	References []any                        `json:"references,omitempty"`
}

// DashboardsFindResponse is the response from Dashboards saved object search.
type DashboardsFindResponse struct {
	Page         int                             `json:"page"`
	PerPage      int                             `json:"per_page"`
	Total        int                             `json:"total"`
	SavedObjects []DashboardsSavedObjectResponse `json:"saved_objects"`
}

// DashboardsSettingValueRequest writes a Dashboards advanced setting value.
type DashboardsSettingValueRequest struct {
	Value string `json:"value"`
}

// TenantRequest creates an OpenSearch tenant.
type TenantRequest struct {
	Description string `json:"description"`
}

// SecurityRoleRequest describes an OpenSearch security role definition.
type SecurityRoleRequest struct {
	ClusterPermissions []string                   `json:"cluster_permissions"`
	IndexPermissions   []SecurityIndexPermission  `json:"index_permissions"`
	TenantPermissions  []SecurityTenantPermission `json:"tenant_permissions"`
}

// SecurityIndexPermission grants index-level permissions to a role.
type SecurityIndexPermission struct {
	IndexPatterns  []string `json:"index_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

// SecurityTenantPermission grants tenant-level permissions to a role.
type SecurityTenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

// InternalUserRequest describes the payload for an OpenSearch internal user.
type InternalUserRequest struct {
	Hash                    string            `json:"hash,omitempty"`
	Password                string            `json:"password,omitempty"`
	OpenDistroSecurityRoles []string          `json:"opendistro_security_roles"`
	BackendRoles            []string          `json:"backend_roles,omitempty"`
	Attributes              map[string]string `json:"attributes,omitempty"`
}

// SecurityUserInfo is the subset of internal-user metadata the gateway needs.
type SecurityUserInfo struct {
	Reserved bool `json:"reserved"`
	Hidden   bool `json:"hidden"`
}

// ISMPolicyRequest wraps an ISM policy payload.
type ISMPolicyRequest struct {
	Policy ISMPolicy `json:"policy"`
}

// ISMPolicyResponse is the OpenSearch ISM policy response used for upserts.
type ISMPolicyResponse struct {
	SeqNo       int64     `json:"_seq_no"`
	PrimaryTerm int64     `json:"_primary_term"`
	Policy      ISMPolicy `json:"policy"`
}

// ISMPolicy describes an index state management policy.
type ISMPolicy struct {
	Description  string     `json:"description"`
	DefaultState string     `json:"default_state"`
	States       []ISMState `json:"states"`
}

// ISMState describes a single state inside an ISM policy.
type ISMState struct {
	Name        string          `json:"name"`
	Actions     []ISMAction     `json:"actions"`
	Transitions []ISMTransition `json:"transitions"`
}

// ISMAction describes a state action inside an ISM policy.
type ISMAction struct {
	Rollover *ISMRolloverAction `json:"rollover,omitempty"`
}

// ISMRolloverAction configures rollover thresholds for an ISM policy.
type ISMRolloverAction struct {
	MinDocCount int `json:"min_doc_count,omitempty"`
}

// ISMTransition describes a transition between ISM states.
type ISMTransition struct {
	StateName  string         `json:"state_name,omitempty"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

// NewClient constructs a client for OpenSearch and Dashboards APIs.
func NewClient(cfg config.Config) *Client {
	return &Client{Config: cfg}
}

// MarkTenantEnsured caches a successfully ensured tenant.
func (c *Client) MarkTenantEnsured(tenantName string) {
	c.EnsuredTenants.Store(tenantName, true)
}

// MarkDataViewEnsured caches a successfully ensured tenant/data-view pair.
func (c *Client) MarkDataViewEnsured(cacheKey string) {
	c.EnsuredDataViews.Store(cacheKey, true)
}

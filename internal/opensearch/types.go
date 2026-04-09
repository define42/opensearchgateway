package opensearch

import (
	"errors"
	"fmt"
	"sync"

	"github.com/define42/opensearchgateway/internal/config"
)

const (
	DefaultISMPolicyID       = "generic-rollover-100m"
	DefaultIndexTemplateName = "gateway-rollover-template"
)

var ErrReservedInternalUser = errors.New("opensearch internal user is reserved or hidden")

type Client struct {
	Config           config.Config
	EnsuredTenants   sync.Map
	EnsuredDataViews sync.Map
}

type ResponseError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("%s %s failed: status=%d body=%s", e.Method, e.Path, e.StatusCode, e.Body)
}

type IngestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

type IndexDocumentResponse struct {
	ID     string `json:"_id"`
	Result string `json:"result"`
}

type DashboardsSavedObjectRequest struct {
	Attributes DashboardsDataViewAttributes `json:"attributes"`
}

type DashboardsDataViewAttributes struct {
	Title         string `json:"title"`
	TimeFieldName string `json:"timeFieldName"`
}

type DashboardsSavedObjectResponse struct {
	ID         string                       `json:"id"`
	Type       string                       `json:"type"`
	Attributes DashboardsDataViewAttributes `json:"attributes"`
	References []any                        `json:"references,omitempty"`
}

type DashboardsFindResponse struct {
	Page         int                             `json:"page"`
	PerPage      int                             `json:"per_page"`
	Total        int                             `json:"total"`
	SavedObjects []DashboardsSavedObjectResponse `json:"saved_objects"`
}

type DashboardsSettingValueRequest struct {
	Value string `json:"value"`
}

type TenantRequest struct {
	Description string `json:"description"`
}

type SecurityRoleRequest struct {
	ClusterPermissions []string                   `json:"cluster_permissions"`
	IndexPermissions   []SecurityIndexPermission  `json:"index_permissions"`
	TenantPermissions  []SecurityTenantPermission `json:"tenant_permissions"`
}

type SecurityIndexPermission struct {
	IndexPatterns  []string `json:"index_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

type SecurityTenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

type InternalUserRequest struct {
	Hash                    string            `json:"hash,omitempty"`
	Password                string            `json:"password,omitempty"`
	OpenDistroSecurityRoles []string          `json:"opendistro_security_roles"`
	BackendRoles            []string          `json:"backend_roles,omitempty"`
	Attributes              map[string]string `json:"attributes,omitempty"`
}

type SecurityUserInfo struct {
	Reserved bool `json:"reserved"`
	Hidden   bool `json:"hidden"`
}

type ISMPolicyRequest struct {
	Policy ISMPolicy `json:"policy"`
}

type ISMPolicyResponse struct {
	SeqNo       int64     `json:"_seq_no"`
	PrimaryTerm int64     `json:"_primary_term"`
	Policy      ISMPolicy `json:"policy"`
}

type ISMPolicy struct {
	Description  string     `json:"description"`
	DefaultState string     `json:"default_state"`
	States       []ISMState `json:"states"`
}

type ISMState struct {
	Name        string          `json:"name"`
	Actions     []ISMAction     `json:"actions"`
	Transitions []ISMTransition `json:"transitions"`
}

type ISMAction struct {
	Rollover *ISMRolloverAction `json:"rollover,omitempty"`
}

type ISMRolloverAction struct {
	MinDocCount int `json:"min_doc_count,omitempty"`
}

type ISMTransition struct {
	StateName  string         `json:"state_name,omitempty"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

func NewClient(cfg config.Config) *Client {
	return &Client{Config: cfg}
}

func (c *Client) MarkTenantEnsured(tenantName string) {
	c.EnsuredTenants.Store(tenantName, true)
}

func (c *Client) MarkDataViewEnsured(cacheKey string) {
	c.EnsuredDataViews.Store(cacheKey, true)
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	authzpkg "github.com/define42/opensearchgateway/internal/authz"
	appconfig "github.com/define42/opensearchgateway/internal/config"
	ingestpkg "github.com/define42/opensearchgateway/internal/ingest"
	ldappkg "github.com/define42/opensearchgateway/internal/ldap"
	opensearchpkg "github.com/define42/opensearchgateway/internal/opensearch"
	serverpkg "github.com/define42/opensearchgateway/internal/server"
	sessionpkg "github.com/define42/opensearchgateway/internal/session"
	goldap "github.com/go-ldap/ldap/v3"
)

type Config = appconfig.Config
type LDAPConfig = appconfig.LDAPConfig
type User = authzpkg.User
type Access = authzpkg.Access
type ldapAuthenticator = serverpkg.AuthenticateFunc
type sessionData = sessionpkg.Data
type ingestResponse = serverpkg.IngestResponse
type errorResponse = serverpkg.ErrorResponse
type loginPageData = serverpkg.LoginPageData
type ResponseError = opensearchpkg.ResponseError
type dashboardsFindResponse = opensearchpkg.DashboardsFindResponse
type dashboardsSavedObjectResponse = opensearchpkg.DashboardsSavedObjectResponse
type securityRoleRequest = opensearchpkg.SecurityRoleRequest
type securityIndexPermission = opensearchpkg.SecurityIndexPermission
type securityTenantPermission = opensearchpkg.SecurityTenantPermission
type dashboardsSavedObjectRequest = opensearchpkg.DashboardsSavedObjectRequest
type dashboardsSettingValueRequest = opensearchpkg.DashboardsSettingValueRequest
type ismPolicyResponse = opensearchpkg.ISMPolicyResponse
type ismPolicy = opensearchpkg.ISMPolicy
type ingestAuthCache = ingestpkg.AuthCache
type ingestAuthCacheStats = ingestpkg.AuthCacheStats

const (
	defaultPassword      = appconfig.DefaultPassword
	defaultTenant        = appconfig.DefaultTenant
	sessionCookieName    = serverpkg.SessionCookieName
	ismPolicyID          = opensearchpkg.DefaultISMPolicyID
	indexTemplateName    = opensearchpkg.DefaultIndexTemplateName
	ingestAuthCacheTTL   = ingestpkg.CacheTTL
	maxIndexNameBytes    = ingestpkg.MaxIndexNameBytes
	defaultListenAddr    = appconfig.DefaultListenAddr
	defaultOpenSearchURL = appconfig.DefaultOpenSearchURL
	defaultDashboardsURL = appconfig.DefaultDashboardsURL
	defaultUsername      = appconfig.DefaultUsername
)

var (
	errLDAPInvalidCredentials = ldappkg.ErrInvalidCredentials
	errLDAPUserNotFound       = ldappkg.ErrUserNotFound
	errLDAPUnauthorized       = ldappkg.ErrUnauthorized
	errReservedInternalUser   = opensearchpkg.ErrReservedInternalUser
	ldapCfg                   = appconfig.LoadLDAP()
)

type Client struct {
	*opensearchpkg.Client
	ensuredTenants   *sync.Map
	ensuredDataViews *sync.Map
}

type Gateway struct {
	*serverpkg.Gateway
	sessions        *sessionpkg.Store
	ingestAuthCache *ingestpkg.AuthCache
}

func defaultHTTPClient() *http.Client {
	return appconfig.DefaultHTTPClient()
}

func mustParse(s string) *url.URL {
	return appconfig.MustParse(s)
}

func getenv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func loadLDAPConfig() LDAPConfig {
	return appconfig.LoadLDAP()
}

func ldapAuthenticateAccess(username, password string) (*User, []Access, error) {
	return ldappkg.New(ldapCfg).AuthenticateAccess(username, password)
}

func newClient(cfg Config) *Client {
	client := opensearchpkg.NewClient(cfg)
	return &Client{
		Client:           client,
		ensuredTenants:   &client.EnsuredTenants,
		ensuredDataViews: &client.EnsuredDataViews,
	}
}

func newGateway(client *Client, authenticate ldapAuthenticator) *Gateway {
	if authenticate == nil {
		authenticate = defaultTestLDAPAuthenticator
	}
	gateway := serverpkg.New(client.Client, authenticate)
	return &Gateway{
		Gateway:         gateway,
		sessions:        gateway.Sessions,
		ingestAuthCache: gateway.IngestAuthCache,
	}
}

func (g *Gateway) handleDashboards(w http.ResponseWriter, r *http.Request) {
	g.Handler().ServeHTTP(w, r)
}

func (g *Gateway) handleDemo(w http.ResponseWriter, r *http.Request) {
	g.Handler().ServeHTTP(w, r)
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	g.Handler().ServeHTTP(w, r)
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	g.Handler().ServeHTTP(w, r)
}

func (g *Gateway) renderLoginPage(w http.ResponseWriter, status int, data loginPageData) {
	g.RenderLoginPage(w, status, data)
}

func (g *Gateway) modifyDashboardsResponse(resp *http.Response, data sessionData) error {
	return g.ModifyDashboardsResponse(resp, data)
}

func (c *Client) setDashboardsDefaultIndex(ctx context.Context, tenantName, dataViewID string) error {
	return c.SetDashboardsDefaultIndex(ctx, tenantName, dataViewID)
}

func (c *Client) doDashboardsJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.DoDashboardsJSON(ctx, method, path, body, out, okStatuses)
}

func (c *Client) doJSONWithRequest(ctx context.Context, method, path string, body any, out any, okStatuses []int, buildRequest func(context.Context, string, string, io.Reader) (*http.Request, error)) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, buildRequest)
}

func (c *Client) newDashboardsRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.NewDashboardsRequest(ctx, method, path, body)
}

func (c *Client) aliasExists(ctx context.Context, alias string) (bool, error) {
	return c.AliasExists(ctx, alias)
}

func (c *Client) ensureInternalUserWritable(ctx context.Context, username string) error {
	return c.EnsureInternalUserWritable(ctx, username)
}

func newIngestAuthCache() *ingestAuthCache {
	return ingestpkg.NewAuthCache()
}

func ingestAuthCacheKey(username, password string) string {
	return ingestpkg.AuthCacheKey(username, password)
}

func permissionsFromGroup(group string) (string, bool, bool, bool) {
	return ldappkg.PermissionsFromGroup(group)
}

func groupNameFromDN(dn string) string {
	return ldappkg.GroupNameFromDN(dn)
}

func accessFromGroups(username string, groups []string, prefix string) ([]Access, *User) {
	return ldappkg.AccessFromGroups(username, groups, prefix)
}

func dialLDAP(cfg LDAPConfig) (*goldap.Conn, error) {
	return ldappkg.Dial(cfg)
}

func morePermissive(a, b *User) bool {
	return authzpkg.MorePermissive(a, b)
}

func parseIngestPath(path string) (string, error) {
	return ingestpkg.ParsePath(path)
}

func decodeJSONObject(body io.Reader) (map[string]any, error) {
	return ingestpkg.DecodeJSONObject(body)
}

func parseEventTime(document map[string]any) (time.Time, error) {
	return ingestpkg.ParseEventTime(document)
}

func buildWriteAlias(indexName string, eventTime time.Time) string {
	return ingestpkg.BuildWriteAlias(indexName, eventTime)
}

func buildFirstBackingIndex(alias string) string {
	return ingestpkg.BuildFirstBackingIndex(alias)
}

func normalizeAccessByNamespace(access []Access) []Access {
	return authzpkg.NormalizeAccessByNamespace(access)
}

func accessGroupNames(access []Access) []string {
	return authzpkg.AccessGroupNames(access)
}

func roleModeForAccess(access Access) string {
	return authzpkg.RoleModeForAccess(access)
}

func roleRequestForAccess(access Access) securityRoleRequest {
	return opensearchpkg.RoleRequestForAccess(access)
}

func buildDataViewID(indexName string) string {
	return opensearchpkg.BuildDataViewID(indexName)
}

func buildDataViewPattern(indexName string) string {
	return opensearchpkg.BuildDataViewPattern(indexName)
}

func dashboardsAPIPath(path string) string {
	return opensearchpkg.DashboardsAPIPath(path)
}

func isDashboardsIndexPatternFindRequest(req *http.Request) bool {
	return serverpkg.IsDashboardsIndexPatternFindRequest(req)
}

func matchesIndexPatternFindQuery(values url.Values, tenantName string) bool {
	return serverpkg.MatchesIndexPatternFindQuery(values, tenantName)
}

func sessionHasNamespace(data sessionData, tenantName string) bool {
	return serverpkg.SessionHasNamespace(data, tenantName)
}

func buildBasicAuthorization(username, password string) string {
	return serverpkg.BuildBasicAuthorization(username, password)
}

func forwardedProto(r *http.Request) string {
	return serverpkg.ForwardedProto(r)
}

func isRetryableBootstrapConflict(err error) bool {
	return opensearchpkg.IsRetryableBootstrapConflict(err)
}

func buildISMPolicy(minDocCount int) ismPolicy {
	return opensearchpkg.BuildISMPolicy(minDocCount)
}

type sessionStore = sessionpkg.Store

func newSessionStore() *sessionStore {
	return sessionpkg.NewStore()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

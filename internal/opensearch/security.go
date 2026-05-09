package opensearch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/define42/opensearchgateway/internal/authz"
	"golang.org/x/crypto/bcrypt"
)

// ProvisionLoginUser ensures roles, tenants, data views, and the internal user.
//
// internalUserPassword is the password to set on the OpenSearch internal user
// for username. It is NOT the caller's LDAP password: the gateway mints a fresh
// random value per login so the LDAP credential never reaches OpenSearch's
// internal user database. Callers must keep that value out of any persistent
// store other than the gateway's session cookie.
func (c *Client) ProvisionLoginUser(ctx context.Context, username, internalUserPassword string, access []authz.Access) error {
	effective := authz.NormalizeAccessByNamespace(access)
	if len(effective) == 0 {
		return fmt.Errorf("no LDAP namespaces available for %s", username)
	}

	if err := c.EnsureInternalUserWritable(ctx, username); err != nil {
		return err
	}

	roleNames := make([]string, 0, len(effective)+1)
	namespaces := make([]string, 0, len(effective))
	for _, item := range effective {
		if !authz.ValidNamespace(item.Namespace) {
			return fmt.Errorf("LDAP namespace %q cannot be mapped to OpenSearch resources", item.Namespace)
		}

		roleName := authz.BuildGatewayRoleName(item.Namespace, authz.RoleModeForAccess(item))
		if err := c.EnsureSecurityRole(ctx, roleName, item); err != nil {
			return err
		}
		if err := c.EnsureDashboardDataView(ctx, item.Namespace, item.Namespace); err != nil {
			return err
		}

		roleNames = append(roleNames, roleName)
		namespaces = append(namespaces, item.Namespace)
	}

	sort.Strings(roleNames)
	sort.Strings(namespaces)
	roleNames = append([]string{"kibana_user"}, roleNames...)

	return c.UpsertInternalUser(ctx, username, internalUserPassword, roleNames, authz.AccessGroupNames(access), namespaces)
}

// EnsureSecurityRole upserts the OpenSearch role used for a namespace access mode.
func (c *Client) EnsureSecurityRole(ctx context.Context, roleName string, access authz.Access) error {
	path := "/_plugins/_security/api/roles/" + url.PathEscape(roleName)
	body := RoleRequestForAccess(access)
	if err := c.DoJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return fmt.Errorf("ensure security role %q: %w", roleName, err)
	}
	return nil
}

// RoleRequestForAccess converts namespace access into an OpenSearch role payload.
func RoleRequestForAccess(access authz.Access) SecurityRoleRequest {
	mode := authz.RoleModeForAccess(access)

	clusterPermissions := []string{"cluster_composite_ops_ro", "indices_monitor"}
	if mode == "rw" || mode == "rwd" {
		clusterPermissions = []string{"cluster_composite_ops", "indices_monitor"}
	}
	clusterPermissions = append(clusterPermissions, "cluster:admin/opensearch/ql/datasources/read")

	return SecurityRoleRequest{
		ClusterPermissions: clusterPermissions,
		IndexPermissions: []SecurityIndexPermission{
			{
				IndexPatterns:  []string{BuildDataViewPattern(access.Namespace)},
				AllowedActions: authz.AllowedActionsForAccess(mode),
			},
			{
				IndexPatterns:  []string{"*"},
				AllowedActions: []string{"indices:admin/resolve/index"},
			},
		},
		TenantPermissions: []SecurityTenantPermission{
			{
				TenantPatterns: []string{access.Namespace},
				AllowedActions: []string{"kibana_all_write"},
			},
		},
	}
}

// UpsertInternalUser creates or replaces an OpenSearch internal user.
//
// internalUserPassword is bcrypt-hashed and stored on the OpenSearch internal
// user record. It is NOT an LDAP credential: the gateway generates a random
// value per login so the LDAP password never reaches OpenSearch.
func (c *Client) UpsertInternalUser(ctx context.Context, username, internalUserPassword string, roleNames, backendRoles, namespaces []string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(internalUserPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash OpenSearch password for %q: %w", username, err)
	}

	body := InternalUserRequest{
		Hash:                    string(passwordHash),
		OpenDistroSecurityRoles: roleNames,
		BackendRoles:            backendRoles,
		Attributes: map[string]string{
			"namespaces": strings.Join(namespaces, ","),
		},
	}

	path := "/_plugins/_security/api/internalusers/" + url.PathEscape(username)
	if err := c.DoJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return fmt.Errorf("upsert OpenSearch user %q: %w", username, err)
	}
	return nil
}

// EnsureInternalUserWritable rejects reserved or hidden internal users.
func (c *Client) EnsureInternalUserWritable(ctx context.Context, username string) error {
	path := "/_plugins/_security/api/internalusers/" + url.PathEscape(username)

	var response map[string]SecurityUserInfo
	err := c.DoJSON(ctx, http.MethodGet, path, nil, &response, []int{http.StatusOK})
	if err != nil {
		if IsNotFoundResponse(err) {
			return nil
		}
		return err
	}

	info, ok := response[username]
	if !ok {
		return nil
	}
	if info.Reserved || info.Hidden {
		return fmt.Errorf("%w: %s", ErrReservedInternalUser, username)
	}
	return nil
}

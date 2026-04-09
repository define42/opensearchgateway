package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/define42/opensearchgateway/internal/authz"
	"github.com/define42/opensearchgateway/internal/config"
	goldap "github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidCredentials = errors.New("ldap invalid credentials")
	ErrUserNotFound       = errors.New("ldap user not found")
	ErrUnauthorized       = errors.New("ldap user has no authorized groups")
)

type Authenticator struct {
	cfg config.LDAPConfig
}

func New(cfg config.LDAPConfig) *Authenticator {
	return &Authenticator{cfg: cfg}
}

func (a *Authenticator) AuthenticateAccess(username, password string) (*authz.User, []authz.Access, error) {
	conn, err := Dial(a.cfg)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	mail := username
	if !strings.Contains(username, "@") && a.cfg.UserMailDomain != "" {
		domain := a.cfg.UserMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		if goldap.IsErrorWithCode(bindErr, goldap.LDAPResultInvalidCredentials) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}

	filter := fmt.Sprintf(a.cfg.UserFilter, mail)
	searchReq := goldap.NewSearchRequest(
		a.cfg.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases, 1, 0, false,
		filter,
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, nil, fmt.Errorf("%w: %s", ErrUserNotFound, mail)
	}

	entry := sr.Entries[0]
	groups := entry.GetAttributeValues(a.cfg.GroupAttribute)
	access, user := AccessFromGroups(username, groups, a.cfg.GroupNamePrefix)
	if user == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnauthorized, username)
	}

	return user, access, nil
}

func Dial(cfg config.LDAPConfig) (*goldap.Conn, error) {
	conn, err := goldap.DialURL(cfg.URL, goldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify})) // #nosec G402
	if err != nil {
		return nil, err
	}

	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}); err != nil { // #nosec G402
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func AccessFromGroups(username string, groups []string, prefix string) ([]authz.Access, *authz.User) {
	var selected *authz.User
	var access []authz.Access

	for _, g := range groups {
		groupName := GroupNameFromDN(g)
		if prefix != "" && !strings.HasPrefix(groupName, prefix) {
			continue
		}

		ns, pullOnly, deleteAllowed, ok := PermissionsFromGroup(groupName)
		if !ok {
			continue
		}

		access = append(access, authz.Access{
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		})

		candidate := &authz.User{
			Name:          username,
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		}

		if selected == nil || authz.MorePermissive(candidate, selected) {
			selected = candidate
		}
	}

	return access, selected
}

func GroupNameFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}

	first := strings.TrimSpace(parts[0])
	firstLower := strings.ToLower(first)

	switch {
	case strings.HasPrefix(firstLower, "cn="):
		return first[3:]
	case strings.HasPrefix(firstLower, "ou="):
		return first[3:]
	default:
		return dn
	}
}

func PermissionsFromGroup(group string) (namespace string, pullOnly bool, deleteAllowed bool, ok bool) {
	switch {
	case strings.HasSuffix(group, "_rwd"):
		ns := strings.TrimSuffix(group, "_rwd")
		return ns, false, true, true
	case strings.HasSuffix(group, "_rw"):
		ns := strings.TrimSuffix(group, "_rw")
		return ns, false, false, true
	case strings.HasSuffix(group, "_rd"):
		ns := strings.TrimSuffix(group, "_rd")
		return ns, true, true, true
	case strings.HasSuffix(group, "_r"):
		ns := strings.TrimSuffix(group, "_r")
		return ns, true, false, true
	default:
		return "", false, false, false
	}
}

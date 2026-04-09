package authz

import "sort"

type User struct {
	Name          string
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

type Access struct {
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

func MorePermissive(a, b *User) bool {
	if a.DeleteAllowed != b.DeleteAllowed {
		return a.DeleteAllowed
	}
	if a.PullOnly != b.PullOnly {
		return !a.PullOnly
	}
	return false
}

func NormalizeAccessByNamespace(access []Access) []Access {
	combined := make(map[string]Access)

	for _, item := range access {
		existing, ok := combined[item.Namespace]
		if !ok {
			combined[item.Namespace] = item
			continue
		}

		existing.PullOnly = existing.PullOnly && item.PullOnly
		existing.DeleteAllowed = existing.DeleteAllowed || item.DeleteAllowed
		if existing.Group == "" {
			existing.Group = item.Group
		}
		combined[item.Namespace] = existing
	}

	namespaces := make([]string, 0, len(combined))
	for namespace := range combined {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	result := make([]Access, 0, len(namespaces))
	for _, namespace := range namespaces {
		result = append(result, combined[namespace])
	}
	return result
}

func AccessGroupNames(access []Access) []string {
	seen := make(map[string]struct{})
	groups := make([]string, 0, len(access))
	for _, item := range access {
		if item.Group == "" {
			continue
		}
		if _, ok := seen[item.Group]; ok {
			continue
		}
		seen[item.Group] = struct{}{}
		groups = append(groups, item.Group)
	}
	sort.Strings(groups)
	return groups
}

func CloneAccess(access []Access) []Access {
	if len(access) == 0 {
		return nil
	}

	cloned := make([]Access, len(access))
	copy(cloned, access)
	return cloned
}

func HasIngestWriteAccess(access []Access, indexName string) bool {
	for _, item := range NormalizeAccessByNamespace(access) {
		if item.Namespace == indexName && !item.PullOnly {
			return true
		}
	}
	return false
}

func RoleModeForAccess(access Access) string {
	switch {
	case !access.PullOnly && access.DeleteAllowed:
		return "rwd"
	case !access.PullOnly:
		return "rw"
	case access.DeleteAllowed:
		return "rd"
	default:
		return "r"
	}
}

func BuildGatewayRoleName(namespace, mode string) string {
	return "gateway_" + namespace + "_" + mode
}

func AllowedActionsForAccess(mode string) []string {
	switch mode {
	case "rwd":
		return []string{"crud"}
	case "rw":
		return []string{"read", "write"}
	case "rd":
		return []string{"read", "delete"}
	default:
		return []string{"read"}
	}
}

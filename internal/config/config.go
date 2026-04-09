package config

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DefaultListenAddr    = ":8080"
	DefaultOpenSearchURL = "https://localhost:9200"
	DefaultDashboardsURL = "http://localhost:5601"
	DefaultUsername      = "admin"
	DefaultPassword      = "Cedar7!FluxOrbit29"
	DefaultTenant        = "admin_tenant"
)

type Config struct {
	BaseURL            string
	Username           string
	Password           string
	DashboardsURL      string
	DashboardsUsername string
	DashboardsPassword string
	DashboardsTenant   string
	ListenAddr         string
	Shards             int
	Replicas           int
	HTTPClient         *http.Client
}

type LDAPConfig struct {
	URL             string
	BaseDN          string
	UserFilter      string
	GroupAttribute  string
	GroupNamePrefix string
	UserMailDomain  string
	StartTLS        bool
	SkipTLSVerify   bool
}

func MustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local/dev only
		},
	}
}

func LoadGateway() Config {
	return Config{
		BaseURL:            getEnv("OPENSEARCH_URL", DefaultOpenSearchURL),
		Username:           getEnv("OPENSEARCH_USERNAME", DefaultUsername),
		Password:           getEnv("OPENSEARCH_PASSWORD", DefaultPassword),
		DashboardsURL:      getEnv("DASHBOARDS_URL", DefaultDashboardsURL),
		DashboardsUsername: getEnv("DASHBOARDS_USERNAME", getEnv("OPENSEARCH_USERNAME", DefaultUsername)),
		DashboardsPassword: getEnv("DASHBOARDS_PASSWORD", getEnv("OPENSEARCH_PASSWORD", DefaultPassword)),
		DashboardsTenant:   getEnv("DASHBOARDS_TENANT", DefaultTenant),
		ListenAddr:         getEnv("LISTEN_ADDR", DefaultListenAddr),
		Shards:             2,
		Replicas:           2,
		HTTPClient:         DefaultHTTPClient(),
	}
}

func LoadLDAP() LDAPConfig {
	return LDAPConfig{
		URL:             getEnv("LDAP_URL", "ldaps://ldap:389"),
		BaseDN:          getEnv("LDAP_BASE_DN", "dc=glauth,dc=com"),
		UserFilter:      getEnv("LDAP_USER_FILTER", "(mail=%s)"),
		GroupAttribute:  getEnv("LDAP_GROUP_ATTRIBUTE", "memberOf"),
		GroupNamePrefix: getEnv("LDAP_GROUP_PREFIX", "team"),
		UserMailDomain:  getEnv("LDAP_USER_DOMAIN", "@example.com"),
		StartTLS:        getEnvBool("LDAP_STARTTLS", false),
		SkipTLSVerify:   getEnvBool("LDAP_SKIP_TLS_VERIFY", true),
	}
}

func getEnv(key, def string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		value = strings.ToLower(strings.TrimSpace(value))
		return value == "1" || value == "true" || value == "yes"
	}
	return def
}

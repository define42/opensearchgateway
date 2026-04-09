// Package config loads environment-backed gateway and LDAP configuration.
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
	// DefaultListenAddr is the gateway bind address used when LISTEN_ADDR is unset.
	DefaultListenAddr = ":8080"
	// DefaultOpenSearchURL is the default OpenSearch endpoint.
	DefaultOpenSearchURL = "https://localhost:9200"
	// DefaultDashboardsURL is the default Dashboards endpoint.
	DefaultDashboardsURL = "http://localhost:5601"
	// DefaultUsername is the default upstream admin username.
	DefaultUsername = "admin"
	// DefaultTenant is the default Dashboards tenant for generic proxy requests.
	DefaultTenant = "admin_tenant"
)

// Config contains runtime settings for OpenSearch, Dashboards, and HTTP serving.
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

// LDAPConfig contains runtime settings for the gateway's LDAP client.
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

// MustParse parses s as a URL and panics on failure.
func MustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// DefaultHTTPClient builds the default upstream HTTP client for the gateway.
func DefaultHTTPClient() *http.Client {
	transport := &http.Transport{}
	if getEnvBool("OPENSEARCH_SKIP_TLS_VERIFY", false) {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit local-dev opt-in for self-signed OpenSearch
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// LoadGateway loads gateway configuration from the environment.
func LoadGateway() Config {
	defaultPassword := getEnv("OPENSEARCH_ADMIN_PASSWORD", "")

	return Config{
		BaseURL:            getEnv("OPENSEARCH_URL", DefaultOpenSearchURL),
		Username:           getEnv("OPENSEARCH_USERNAME", DefaultUsername),
		Password:           getEnv("OPENSEARCH_PASSWORD", defaultPassword),
		DashboardsURL:      getEnv("DASHBOARDS_URL", DefaultDashboardsURL),
		DashboardsUsername: getEnv("DASHBOARDS_USERNAME", getEnv("OPENSEARCH_USERNAME", DefaultUsername)),
		DashboardsPassword: getEnv("DASHBOARDS_PASSWORD", getEnv("OPENSEARCH_PASSWORD", defaultPassword)),
		DashboardsTenant:   getEnv("DASHBOARDS_TENANT", DefaultTenant),
		ListenAddr:         getEnv("LISTEN_ADDR", DefaultListenAddr),
		Shards:             2,
		Replicas:           2,
		HTTPClient:         DefaultHTTPClient(),
	}
}

// LoadLDAP loads LDAP configuration from the environment.
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

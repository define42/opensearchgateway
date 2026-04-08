package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultListenAddr    = ":8080"
	defaultOpenSearchURL = "https://localhost:9200"
	defaultDashboardsURL = "http://localhost:5601"
	defaultUsername      = "admin"
	defaultPassword      = "Cedar7!FluxOrbit29"
	defaultTenant        = "admin_tenant"

	ismPolicyID       = "generic-rollover-100m"
	indexTemplateName = "gateway-rollover-template"
	rolloverSuffix    = "-rollover"
	backingIndexSeed  = "-000001"

	maxIndexNameBytes = 255
	sessionCookieName = "opensearchgateway_session"
)

var (
	indexNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	errRouteNotFound = errors.New("route not found")

	errIngestAuthRequired = errors.New("ingest authentication required")
	errIngestForbidden    = errors.New("ingest user is not allowed to write to this index")
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

type Client struct {
	cfg              Config
	ensuredTenants   sync.Map
	ensuredDataViews sync.Map
}

type ldapAuthenticator func(string, string) (*User, []Access, error)

type Gateway struct {
	client       *Client
	authenticate ldapAuthenticator
	sessions     *sessionStore
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionData
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

type ismPolicyRequest struct {
	Policy ismPolicy `json:"policy"`
}

type ismPolicyResponse struct {
	SeqNo       int64     `json:"_seq_no"`
	PrimaryTerm int64     `json:"_primary_term"`
	Policy      ismPolicy `json:"policy"`
}

type ismPolicy struct {
	Description  string     `json:"description"`
	DefaultState string     `json:"default_state"`
	States       []ismState `json:"states"`
}

type ismState struct {
	Name        string          `json:"name"`
	Actions     []ismAction     `json:"actions"`
	Transitions []ismTransition `json:"transitions"`
}

type ismAction struct {
	Rollover *ismRolloverAction `json:"rollover,omitempty"`
}

type ismRolloverAction struct {
	MinDocCount int `json:"min_doc_count,omitempty"`
}

type ismTransition struct {
	StateName  string         `json:"state_name,omitempty"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

type ingestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

type indexDocumentResponse struct {
	ID     string `json:"_id"`
	Result string `json:"result"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type dashboardsSavedObjectRequest struct {
	Attributes dashboardsDataViewAttributes `json:"attributes"`
}

type dashboardsDataViewAttributes struct {
	Title         string `json:"title"`
	TimeFieldName string `json:"timeFieldName"`
}

type dashboardsSavedObjectResponse struct {
	ID         string                       `json:"id"`
	Type       string                       `json:"type"`
	Attributes dashboardsDataViewAttributes `json:"attributes"`
	References []any                        `json:"references,omitempty"`
}

type dashboardsFindResponse struct {
	Page         int                             `json:"page"`
	PerPage      int                             `json:"per_page"`
	Total        int                             `json:"total"`
	SavedObjects []dashboardsSavedObjectResponse `json:"saved_objects"`
}

type dashboardsSettingValueRequest struct {
	Value string `json:"value"`
}

type loginPageData struct {
	Error    string
	Username string
}

type tenantRequest struct {
	Description string `json:"description"`
}

type securityRoleRequest struct {
	ClusterPermissions []string                   `json:"cluster_permissions"`
	IndexPermissions   []securityIndexPermission  `json:"index_permissions"`
	TenantPermissions  []securityTenantPermission `json:"tenant_permissions"`
}

type securityIndexPermission struct {
	IndexPatterns  []string `json:"index_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

type securityTenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

type internalUserRequest struct {
	Hash                    string            `json:"hash,omitempty"`
	Password                string            `json:"password,omitempty"`
	OpenDistroSecurityRoles []string          `json:"opendistro_security_roles"`
	BackendRoles            []string          `json:"backend_roles,omitempty"`
	Attributes              map[string]string `json:"attributes,omitempty"`
}

type securityUserInfo struct {
	Reserved bool `json:"reserved"`
	Hidden   bool `json:"hidden"`
}

var errReservedInternalUser = errors.New("opensearch internal user is reserved or hidden")

var loginPageTemplate = template.Must(template.New("login").Parse(loginPageHTML))

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenSearch Gateway Login</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef2e7;
      --panel: rgba(255, 255, 252, 0.94);
      --ink: #1d261c;
      --muted: #617062;
      --accent: #295f4e;
      --accent-strong: #173e32;
      --danger: #a23d3d;
      --border: rgba(47, 71, 56, 0.12);
      --shadow: 0 24px 80px rgba(39, 69, 54, 0.16);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(41, 95, 78, 0.17), transparent 28%),
        radial-gradient(circle at bottom right, rgba(187, 209, 176, 0.3), transparent 32%),
        linear-gradient(160deg, #edf5e8 0%, #fafcf8 52%, #e4ece0 100%);
      display: grid;
      place-items: center;
      padding: 32px 18px;
    }

    main {
      width: min(520px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow);
      overflow: hidden;
      backdrop-filter: blur(12px);
    }

    .hero {
      padding: 32px 32px 18px;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.7), rgba(237, 245, 232, 0.92));
    }

    h1 {
      margin: 0 0 10px;
      font-family: Georgia, "Times New Roman", serif;
      font-size: clamp(2rem, 4vw, 3rem);
      line-height: 1.05;
      letter-spacing: -0.03em;
    }

    .hero p {
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
    }

    form {
      padding: 28px 32px 32px;
      display: grid;
      gap: 18px;
    }

    label {
      display: grid;
      gap: 8px;
      font-weight: 700;
      font-size: 0.96rem;
    }

    input,
    button {
      font: inherit;
    }

    input {
      width: 100%;
      border: 1px solid rgba(47, 71, 56, 0.18);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.92);
      color: var(--ink);
      padding: 14px 16px;
      transition: border-color 120ms ease, box-shadow 120ms ease, transform 120ms ease;
    }

    input:focus {
      outline: none;
      border-color: rgba(41, 95, 78, 0.6);
      box-shadow: 0 0 0 4px rgba(41, 95, 78, 0.12);
      transform: translateY(-1px);
    }

    button {
      border: 0;
      border-radius: 999px;
      padding: 13px 20px;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      color: #f3fbf7;
      font-weight: 800;
      cursor: pointer;
      box-shadow: 0 16px 36px rgba(23, 62, 50, 0.22);
    }

    .hint {
      color: var(--muted);
      font-size: 0.93rem;
      line-height: 1.55;
    }

    .error {
      margin: 0;
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(162, 61, 61, 0.1);
      color: var(--danger);
      font-weight: 700;
    }

    .links {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }

    a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 700;
    }

    @media (max-width: 700px) {
      .hero,
      form {
        padding-left: 20px;
        padding-right: 20px;
      }

      main {
        border-radius: 22px;
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Gateway Login</h1>
      <p>Sign in with your LDAP username and password. The gateway validates the credentials, provisions your OpenSearch account, and then opens OpenSearch Dashboards through the gateway proxy.</p>
    </section>

    <form method="post" action="/login">
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}

      <label for="username">Username</label>
      <input id="username" name="username" type="text" value="{{.Username}}" autocomplete="username" spellcheck="false" required>

      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>

      <button type="submit">Sign In</button>

      <div class="links">
        <span class="hint">Dashboards is proxied through this gateway after sign-in.</span>
        <a href="/demo">Open demo page</a>
      </div>
    </form>
  </main>
</body>
</html>
`

const demoPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenSearch Gateway Demo</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6efe4;
      --panel: rgba(255, 251, 245, 0.94);
      --ink: #1d1a17;
      --muted: #6d625a;
      --accent: #b4492d;
      --accent-strong: #8f3119;
      --border: rgba(76, 51, 38, 0.14);
      --shadow: 0 24px 80px rgba(90, 57, 33, 0.16);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(180, 73, 45, 0.2), transparent 28%),
        radial-gradient(circle at bottom right, rgba(230, 170, 108, 0.24), transparent 32%),
        linear-gradient(160deg, #f2e4d1 0%, #fbf8f3 52%, #efe1cc 100%);
      display: grid;
      place-items: center;
      padding: 32px 18px;
    }

    main {
      width: min(860px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow);
      overflow: hidden;
      backdrop-filter: blur(12px);
    }

    .hero {
      padding: 32px 32px 18px;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.56), rgba(255, 244, 230, 0.82));
    }

    h1 {
      margin: 0 0 10px;
      font-family: Georgia, "Times New Roman", serif;
      font-size: clamp(2rem, 4vw, 3.1rem);
      line-height: 1.05;
      letter-spacing: -0.03em;
    }

    .hero p {
      margin: 0;
      max-width: 62ch;
      color: var(--muted);
      font-size: 1rem;
      line-height: 1.6;
    }

    form {
      padding: 28px 32px 32px;
      display: grid;
      gap: 20px;
    }

    label {
      display: grid;
      gap: 8px;
      font-weight: 700;
      font-size: 0.96rem;
    }

    input,
    textarea,
    button {
      font: inherit;
    }

    input,
    textarea {
      width: 100%;
      border: 1px solid rgba(76, 51, 38, 0.18);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.86);
      color: var(--ink);
      padding: 14px 16px;
      transition: border-color 120ms ease, box-shadow 120ms ease, transform 120ms ease;
    }

    input:focus,
    textarea:focus {
      outline: none;
      border-color: rgba(180, 73, 45, 0.6);
      box-shadow: 0 0 0 4px rgba(180, 73, 45, 0.12);
      transform: translateY(-1px);
    }

    textarea {
      min-height: 280px;
      resize: vertical;
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 0.94rem;
      line-height: 1.55;
    }

    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }

    button {
      border: 0;
      border-radius: 999px;
      padding: 13px 20px;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      color: #fff8f2;
      font-weight: 800;
      cursor: pointer;
      box-shadow: 0 16px 36px rgba(143, 49, 25, 0.22);
    }

    button:hover {
      transform: translateY(-1px);
    }

    .hint {
      color: var(--muted);
      font-size: 0.93rem;
    }

    pre {
      margin: 0;
      padding: 18px;
      border-top: 1px solid var(--border);
      background: #201814;
      color: #f9eee1;
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 0.92rem;
      line-height: 1.55;
      min-height: 160px;
      white-space: pre-wrap;
      word-break: break-word;
    }

    @media (max-width: 700px) {
      .hero,
      form {
        padding-left: 20px;
        padding-right: 20px;
      }

      main {
        border-radius: 22px;
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Gateway Demo Console</h1>
      <p>Send a single JSON document into the gateway. The document must include a top-level <code>event_time</code> field in UTC RFC3339 form, and the gateway will route it to <code>&lt;index&gt;-YYYYMMDD-rollover</code>.</p>
    </section>

    <form id="demo-form">
      <label for="index-name">Index Name</label>
      <input id="index-name" name="index" type="text" value="orders" spellcheck="false" autocomplete="off">

      <label for="username">LDAP Username <span class="hint">(optional when already signed in)</span></label>
      <input id="username" name="username" type="text" spellcheck="false" autocomplete="username">

      <label for="password">LDAP Password <span class="hint">(optional when already signed in)</span></label>
      <input id="password" name="password" type="password" autocomplete="current-password">

      <label for="payload">JSON Payload</label>
      <textarea id="payload" name="payload" spellcheck="false">{
  "event_time": "2024-12-30T10:11:12Z",
  "message": "Demo event from the gateway UI",
  "customer_id": 42,
  "status": "received"
}</textarea>

      <div class="toolbar">
        <button type="submit">Submit Document</button>
        <span class="hint" id="status-text">Ready to send.</span>
      </div>
    </form>

    <pre id="result">No request sent yet.</pre>
  </main>

  <script>
    const form = document.getElementById("demo-form");
    const indexInput = document.getElementById("index-name");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const payloadInput = document.getElementById("payload");
    const result = document.getElementById("result");
    const statusText = document.getElementById("status-text");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const indexName = indexInput.value.trim();
      if (!indexName) {
        statusText.textContent = "Index name is required.";
        result.textContent = "Please enter an index name before submitting.";
        indexInput.focus();
        return;
      }

      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      if ((username && !password) || (!username && password)) {
        statusText.textContent = "Credentials are incomplete.";
        result.textContent = "Enter both LDAP username and password, or leave both blank to use your current sign-in session.";
        if (!username) {
          usernameInput.focus();
        } else {
          passwordInput.focus();
        }
        return;
      }

      statusText.textContent = "Sending request...";
      result.textContent = "Submitting to /ingest/" + indexName;

      const headers = {
        "Content-Type": "application/json"
      };
      if (username && password) {
        headers["Authorization"] = "Basic " + btoa(username + ":" + password);
      }

      try {
        const response = await fetch("/ingest/" + encodeURIComponent(indexName), {
          method: "POST",
          credentials: "same-origin",
          headers,
          body: payloadInput.value
        });

        const text = await response.text();
        statusText.textContent = response.ok ? "Request accepted." : "Request failed.";
        result.textContent = response.status + " " + response.statusText + "\n\n" + text;
      } catch (error) {
        statusText.textContent = "Network error.";
        result.textContent = String(error);
      }
    });
  </script>
</body>
</html>
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := Config{
		BaseURL:            getenv("OPENSEARCH_URL", defaultOpenSearchURL),
		Username:           getenv("OPENSEARCH_USERNAME", defaultUsername),
		Password:           getenv("OPENSEARCH_PASSWORD", defaultPassword),
		DashboardsURL:      getenv("DASHBOARDS_URL", defaultDashboardsURL),
		DashboardsUsername: getenv("DASHBOARDS_USERNAME", getenv("OPENSEARCH_USERNAME", defaultUsername)),
		DashboardsPassword: getenv("DASHBOARDS_PASSWORD", getenv("OPENSEARCH_PASSWORD", defaultPassword)),
		DashboardsTenant:   getenv("DASHBOARDS_TENANT", defaultTenant),
		ListenAddr:         getenv("LISTEN_ADDR", defaultListenAddr),
		Shards:             2,
		Replicas:           2,
		HTTPClient:         defaultHTTPClient(),
	}

	if err := run(ctx, cfg, func(handler http.Handler) error {
		srv := &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()

		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}); err != nil {
		fatal(err)
	}
}

func run(ctx context.Context, cfg Config, serve func(http.Handler) error) error {
	client := &Client{cfg: cfg}

	if err := client.EnsureISMPolicy(ctx, ismPolicyID, 100000000); err != nil {
		return err
	}

	if err := client.EnsureIndexTemplate(ctx, indexTemplateName); err != nil {
		return err
	}

	return serve(newGateway(client, ldapAuthenticateAccess).Handler())
}

func newGateway(client *Client, authenticate ldapAuthenticator) *Gateway {
	if authenticate == nil {
		authenticate = ldapAuthenticateAccess
	}

	return &Gateway{
		client:       client,
		authenticate: authenticate,
		sessions: &sessionStore{
			sessions: make(map[string]sessionData),
		},
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local/dev only
		},
	}
}

func (c *Client) EnsureISMPolicy(ctx context.Context, policyID string, minDocCount int) error {
	path := "/_plugins/_ism/policies/" + url.PathEscape(policyID)
	desired := ismPolicyRequest{
		Policy: buildISMPolicy(minDocCount),
	}

	var existing ismPolicyResponse
	err := c.doJSON(ctx, http.MethodGet, path, nil, &existing, []int{http.StatusOK})
	if err != nil {
		if isNotFoundResponse(err) {
			return c.doJSON(ctx, http.MethodPut, path, desired, nil, []int{http.StatusOK, http.StatusCreated})
		}
		return err
	}

	if reflect.DeepEqual(existing.Policy, desired.Policy) {
		return nil
	}

	updatePath := fmt.Sprintf("%s?if_seq_no=%d&if_primary_term=%d", path, existing.SeqNo, existing.PrimaryTerm)
	return c.doJSON(ctx, http.MethodPut, updatePath, desired, nil, []int{http.StatusOK, http.StatusCreated})
}

func (c *Client) EnsureIndexTemplate(ctx context.Context, templateName string) error {
	body := map[string]any{
		"index_patterns": []string{"*-*-rollover-*"},
		"priority":       100,
		"template": map[string]any{
			"settings": map[string]any{
				"index.number_of_shards":   c.cfg.Shards,
				"index.number_of_replicas": c.cfg.Replicas,
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

	return c.doJSON(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(templateName), body, nil, []int{200, 201})
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleRoot)
	mux.HandleFunc("/login", g.handleLogin)
	mux.HandleFunc("/logout", g.handleLogout)
	mux.HandleFunc("/dashboards", g.handleDashboards)
	mux.HandleFunc("/dashboards/", g.handleDashboards)
	mux.HandleFunc("/demo", g.handleDemo)
	mux.HandleFunc("/ingest", g.handleIngest)
	mux.HandleFunc("/ingest/", g.handleIngest)
	return mux
}

func (g *Gateway) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if _, session, ok := g.currentSession(r); ok && session.ExpiresAt.After(time.Now()) {
			http.Redirect(w, r, "/dashboards/", http.StatusSeeOther)
			return
		}
		g.renderLoginPage(w, http.StatusOK, loginPageData{})
	case http.MethodPost:
		g.handleLoginSubmit(w, r)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/logout" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if token, _, ok := g.currentSession(r); ok {
		g.sessions.Delete(token)
	} else if cookie, err := r.Cookie(sessionCookieName); err == nil {
		g.sessions.Delete(cookie.Value)
	}

	g.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (g *Gateway) handleDashboards(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboards" && !strings.HasPrefix(r.URL.Path, "/dashboards/") {
		http.NotFound(w, r)
		return
	}

	token, session, ok := g.currentSession(r)
	if !ok {
		g.clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session, ok = g.sessions.Touch(token)
	if !ok {
		g.clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	g.setSessionCookie(w, r, token, session.ExpiresAt)
	if err := g.proxyDashboards(w, r, session); err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Dashboards proxy failed: %v", err))
	}
}

func (g *Gateway) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/demo" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	serveDemoPage(w)
}

func (g *Gateway) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		g.renderLoginPage(w, http.StatusBadGateway, loginPageData{Error: "failed to read login form"})
		return
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		g.renderLoginPage(w, http.StatusUnauthorized, loginPageData{
			Error:    "username and password are required",
			Username: username,
		})
		return
	}

	user, access, err := g.authenticate(username, password)
	if err != nil {
		status, message := loginErrorResponse(err)
		g.renderLoginPage(w, status, loginPageData{
			Error:    message,
			Username: username,
		})
		return
	}

	namespaces, err := g.client.ProvisionLoginUser(r.Context(), username, password, access)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errReservedInternalUser) {
			status = http.StatusForbidden
		}
		g.renderLoginPage(w, status, loginPageData{
			Error:    err.Error(),
			Username: username,
		})
		return
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		g.sessions.Delete(cookie.Value)
	}

	token, expiresAt, err := g.sessions.Create(sessionData{
		User:       user,
		Access:     access,
		Namespaces: namespaces,
		AuthHeader: buildBasicAuthorization(username, password),
		CreatedAt:  time.Now(),
	})
	if err != nil {
		g.renderLoginPage(w, http.StatusBadGateway, loginPageData{
			Error:    "failed to create login session",
			Username: username,
		})
		return
	}

	g.setSessionCookie(w, r, token, expiresAt)
	http.Redirect(w, r, "/dashboards/", http.StatusSeeOther)
}

func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	indexName, err := parseIngestPath(r.URL.Path)
	if err != nil {
		if errors.Is(err, errRouteNotFound) {
			http.NotFound(w, r)
			return
		}
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if err := g.authorizeIngestRequest(r, indexName); err != nil {
		switch {
		case errors.Is(err, errIngestAuthRequired), errors.Is(err, errLDAPInvalidCredentials), errors.Is(err, errLDAPUserNotFound):
			writeIngestAuthRequired(w, "LDAP username and password are required for ingest")
		case errors.Is(err, errLDAPUnauthorized), errors.Is(err, errIngestForbidden):
			writeErrorJSON(w, http.StatusForbidden, "your LDAP account is not allowed to ingest into this index")
		default:
			writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("LDAP authentication failed: %v", err))
		}
		return
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeErrorJSON(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}

	document, err := decodeJSONObject(r.Body)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	eventTime, err := parseEventTime(document)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	writeAlias := buildWriteAlias(indexName, eventTime)
	firstIndex := buildFirstBackingIndex(writeAlias)
	if len(writeAlias) > maxIndexNameBytes || len(firstIndex) > maxIndexNameBytes {
		writeErrorJSON(w, http.StatusBadRequest, "generated alias or backing index name exceeds OpenSearch limits")
		return
	}

	document["event_time"] = eventTime.UTC().Format(time.RFC3339)

	if err := g.client.EnsureDashboardDataView(r.Context(), indexName); err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Dashboards setup failed: %v", err))
		return
	}

	bootstrapped, err := g.client.ensureWriteAlias(r.Context(), writeAlias)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("OpenSearch bootstrap failed: %v", err))
		return
	}

	indexed, err := g.client.IndexDocument(r.Context(), writeAlias, document)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("OpenSearch ingest failed: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, ingestResponse{
		Result:       indexed.Result,
		WriteAlias:   writeAlias,
		DocumentID:   indexed.ID,
		Bootstrapped: bootstrapped,
	})
}

func (g *Gateway) renderLoginPage(w http.ResponseWriter, status int, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := loginPageTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
	}
}

func loginErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, errLDAPInvalidCredentials), errors.Is(err, errLDAPUserNotFound):
		return http.StatusUnauthorized, "invalid username or password"
	case errors.Is(err, errLDAPUnauthorized):
		return http.StatusForbidden, "your LDAP account does not grant access to OpenSearch Dashboards"
	default:
		return http.StatusBadGateway, fmt.Sprintf("LDAP authentication failed: %v", err)
	}
}

func (g *Gateway) authorizeIngestRequest(r *http.Request, indexName string) error {
	access, err := g.ingestAccess(r)
	if err != nil {
		return err
	}
	if !hasIngestWriteAccess(access, indexName) {
		return errIngestForbidden
	}
	return nil
}

func (g *Gateway) ingestAccess(r *http.Request) ([]Access, error) {
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
		username, password, ok := r.BasicAuth()
		if !ok || strings.TrimSpace(username) == "" || password == "" {
			return nil, errIngestAuthRequired
		}

		_, access, err := g.authenticate(strings.TrimSpace(username), password)
		if err != nil {
			return nil, err
		}
		return access, nil
	}

	if _, session, ok := g.currentSession(r); ok {
		return session.Access, nil
	}

	return nil, errIngestAuthRequired
}

func hasIngestWriteAccess(access []Access, indexName string) bool {
	for _, item := range normalizeAccessByNamespace(access) {
		if item.Namespace == indexName && !item.PullOnly {
			return true
		}
	}
	return false
}

func (g *Gateway) currentSession(r *http.Request) (string, sessionData, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", sessionData{}, false
	}

	session, ok := g.sessions.Get(cookie.Value)
	if !ok {
		return cookie.Value, sessionData{}, false
	}
	return cookie.Value, session, true
}

func (g *Gateway) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func (g *Gateway) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (g *Gateway) proxyDashboards(w http.ResponseWriter, r *http.Request, session sessionData) error {
	target, err := url.Parse(g.client.cfg.DashboardsURL)
	if err != nil {
		return fmt.Errorf("invalid Dashboards URL: %w", err)
	}

	defaultTenant := sessionDefaultTenant(session)
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		originalDirector(req)
		req.Host = target.Host
		req.Header.Del("Authorization")
		req.Header.Set("Authorization", session.AuthHeader)
		if req.Header.Get("securitytenant") == "" && defaultTenant != "" {
			req.Header.Set("securitytenant", defaultTenant)
		}
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", forwardedProto(r))
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		return g.modifyDashboardsResponse(resp, session)
	}
	proxy.ErrorHandler = func(proxyWriter http.ResponseWriter, proxyRequest *http.Request, proxyErr error) {
		writeErrorJSON(proxyWriter, http.StatusBadGateway, fmt.Sprintf("Dashboards proxy failed: %v", proxyErr))
	}

	proxy.ServeHTTP(w, r)
	return nil
}

func (g *Gateway) modifyDashboardsResponse(resp *http.Response, session sessionData) error {
	if resp == nil || resp.Request == nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK || resp.Request.Method != http.MethodGet {
		return nil
	}
	if !isDashboardsIndexPatternFindRequest(resp.Request) {
		return nil
	}

	tenantName := strings.TrimSpace(resp.Request.Header.Get("securitytenant"))
	if tenantName == "" {
		tenantName = sessionDefaultTenant(session)
	}
	if tenantName == "" || !sessionHasNamespace(session, tenantName) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	restoreBody := func(payload []byte) {
		resp.Body = io.NopCloser(bytes.NewReader(payload))
		resp.ContentLength = int64(len(payload))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	}

	var payload dashboardsFindResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		restoreBody(body)
		return nil
	}
	if payload.Total != 0 || !matchesIndexPatternFindQuery(resp.Request.URL.Query(), tenantName) {
		restoreBody(body)
		return nil
	}

	synthetic := dashboardsFindResponse{
		Page:    payload.Page,
		PerPage: payload.PerPage,
		Total:   1,
		SavedObjects: []dashboardsSavedObjectResponse{
			{
				ID:   buildDataViewID(tenantName),
				Type: "index-pattern",
				Attributes: dashboardsDataViewAttributes{
					Title:         buildDataViewPattern(tenantName),
					TimeFieldName: "event_time",
				},
				References: []any{},
			},
		},
	}
	if payload.Page > 1 || payload.PerPage == 0 {
		synthetic.SavedObjects = []dashboardsSavedObjectResponse{}
	}

	replacement, err := json.Marshal(synthetic)
	if err != nil {
		return err
	}
	restoreBody(replacement)
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	return nil
}

func sessionDefaultTenant(session sessionData) string {
	if len(session.Namespaces) != 1 {
		return ""
	}
	return strings.TrimSpace(session.Namespaces[0])
}

func sessionHasNamespace(session sessionData, tenantName string) bool {
	for _, namespace := range session.Namespaces {
		if strings.TrimSpace(namespace) == tenantName {
			return true
		}
	}
	return false
}

func parseIngestPath(path string) (string, error) {
	if !strings.HasPrefix(path, "/ingest/") {
		return "", errRouteNotFound
	}

	indexName := strings.TrimPrefix(path, "/ingest/")
	indexName = strings.TrimSuffix(indexName, "/")
	if indexName == "" {
		return "", errors.New("path must be /ingest/<index>/")
	}
	if strings.Contains(indexName, "/") {
		return "", errors.New("path must be /ingest/<index>/")
	}
	if !indexNamePattern.MatchString(indexName) {
		return "", errors.New("index name must start with a lowercase letter or digit and contain only lowercase letters, digits, '-' or '_'")
	}
	return indexName, nil
}

func decodeJSONObject(body io.Reader) (map[string]any, error) {
	decoder := json.NewDecoder(body)

	var value any
	if err := decoder.Decode(&value); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("request body must be a JSON object")
		}
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("request body must be a JSON object")
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("request body must contain a single JSON object")
		}
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	return object, nil
}

func parseEventTime(document map[string]any) (time.Time, error) {
	rawValue, ok := document["event_time"]
	if !ok {
		return time.Time{}, errors.New(`missing required field "event_time"`)
	}

	value, ok := rawValue.(string)
	if !ok {
		return time.Time{}, errors.New(`field "event_time" must be a string`)
	}
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New(`field "event_time" must be a UTC RFC3339 timestamp ending in "Z"`)
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New(`field "event_time" must be a valid RFC3339 timestamp`)
	}
	return parsed.UTC(), nil
}

func buildWriteAlias(indexName string, eventTime time.Time) string {
	return fmt.Sprintf("%s-%s%s", indexName, eventTime.UTC().Format("20060102"), rolloverSuffix)
}

func buildFirstBackingIndex(alias string) string {
	return alias + backingIndexSeed
}

func (c *Client) ensureWriteAlias(ctx context.Context, alias string) (bool, error) {
	exists, err := c.aliasExists(ctx, alias)
	if err != nil {
		return false, fmt.Errorf("check alias %q: %w", alias, err)
	}
	if exists {
		return false, nil
	}

	firstIndex := buildFirstBackingIndex(alias)
	if err := c.bootstrapDateStream(ctx, firstIndex, alias); err != nil {
		if isRetryableBootstrapConflict(err) {
			exists, recheckErr := c.aliasExists(ctx, alias)
			if recheckErr != nil {
				return false, fmt.Errorf("re-check alias %q after bootstrap conflict: %w", alias, recheckErr)
			}
			if exists {
				return false, nil
			}
		}
		return false, fmt.Errorf("bootstrap %q: %w", alias, err)
	}

	if err := c.attachISMPolicy(ctx, firstIndex, ismPolicyID); err != nil {
		return false, fmt.Errorf("attach ISM policy to %q: %w", firstIndex, err)
	}

	return true, nil
}

func (c *Client) IndexDocument(ctx context.Context, alias string, document map[string]any) (indexDocumentResponse, error) {
	path := "/" + url.PathEscape(alias) + "/_doc"

	var response indexDocumentResponse
	if err := c.doJSON(ctx, http.MethodPost, path, document, &response, []int{200, 201}); err != nil {
		return indexDocumentResponse{}, err
	}
	return response, nil
}

func (c *Client) ProvisionLoginUser(ctx context.Context, username, password string, access []Access) ([]string, error) {
	effective := normalizeAccessByNamespace(access)
	if len(effective) == 0 {
		return nil, fmt.Errorf("no LDAP namespaces available for %s", username)
	}

	if err := c.ensureInternalUserWritable(ctx, username); err != nil {
		return nil, err
	}

	roleNames := make([]string, 0, len(effective)+1)
	namespaces := make([]string, 0, len(effective))
	for _, item := range effective {
		if !indexNamePattern.MatchString(item.Namespace) {
			return nil, fmt.Errorf("LDAP namespace %q cannot be mapped to OpenSearch resources", item.Namespace)
		}

		roleName := buildGatewayRoleName(item.Namespace, roleModeForAccess(item))
		if err := c.EnsureSecurityRole(ctx, roleName, item); err != nil {
			return nil, err
		}
		if err := c.EnsureDashboardDataView(ctx, item.Namespace); err != nil {
			return nil, err
		}

		roleNames = append(roleNames, roleName)
		namespaces = append(namespaces, item.Namespace)
	}

	sort.Strings(roleNames)
	sort.Strings(namespaces)
	roleNames = append([]string{"kibana_user"}, roleNames...)

	if err := c.UpsertInternalUser(ctx, username, password, roleNames, accessGroupNames(access), namespaces); err != nil {
		return nil, err
	}

	return namespaces, nil
}

func (c *Client) ensureInternalUserWritable(ctx context.Context, username string) error {
	path := "/_plugins/_security/api/internalusers/" + url.PathEscape(username)

	var response map[string]securityUserInfo
	err := c.doJSON(ctx, http.MethodGet, path, nil, &response, []int{http.StatusOK})
	if err != nil {
		if isNotFoundResponse(err) {
			return nil
		}
		return err
	}

	info, ok := response[username]
	if !ok {
		return nil
	}
	if info.Reserved || info.Hidden {
		return fmt.Errorf("%w: %s", errReservedInternalUser, username)
	}
	return nil
}

func (c *Client) EnsureSecurityRole(ctx context.Context, roleName string, access Access) error {
	path := "/_plugins/_security/api/roles/" + url.PathEscape(roleName)
	body := roleRequestForAccess(access)
	if err := c.doJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return fmt.Errorf("ensure security role %q: %w", roleName, err)
	}
	return nil
}

func (c *Client) UpsertInternalUser(ctx context.Context, username, password string, roleNames, backendRoles, namespaces []string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash OpenSearch password for %q: %w", username, err)
	}

	body := internalUserRequest{
		Hash:                    string(passwordHash),
		OpenDistroSecurityRoles: roleNames,
		BackendRoles:            backendRoles,
		Attributes: map[string]string{
			"namespaces": strings.Join(namespaces, ","),
		},
	}

	path := "/_plugins/_security/api/internalusers/" + url.PathEscape(username)
	if err := c.doJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return fmt.Errorf("upsert OpenSearch user %q: %w", username, err)
	}
	return nil
}

func (c *Client) EnsureTenant(ctx context.Context, tenantName string) error {
	if c.cfg.DashboardsURL == "" {
		return nil
	}

	if _, ok := c.ensuredTenants.Load(tenantName); ok {
		return nil
	}

	path := "/_plugins/_security/api/tenants/" + url.PathEscape(tenantName)
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, []int{http.StatusOK})
	if err != nil {
		if !isNotFoundResponse(err) {
			return err
		}

		body := tenantRequest{
			Description: fmt.Sprintf("Gateway tenant for %s", tenantName),
		}
		if err := c.doJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
			return err
		}
	}

	c.ensuredTenants.Store(tenantName, true)
	return nil
}

func (c *Client) EnsureDashboardDataView(ctx context.Context, indexName string) error {
	if c.cfg.DashboardsURL == "" {
		return nil
	}

	if err := c.EnsureTenant(ctx, indexName); err != nil {
		return err
	}

	tenantName := indexName
	dataViewID := buildDataViewID(indexName)
	cacheKey := tenantName + "/" + dataViewID
	if _, ok := c.ensuredDataViews.Load(cacheKey); ok {
		return nil
	}

	body := dashboardsSavedObjectRequest{
		Attributes: dashboardsDataViewAttributes{
			Title:         buildDataViewPattern(indexName),
			TimeFieldName: "event_time",
		},
	}

	path := "/api/saved_objects/index-pattern/" + url.PathEscape(dataViewID) + "?overwrite=true"
	if err := c.doDashboardsJSONInTenant(ctx, tenantName, http.MethodPost, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return err
	}
	if err := c.setDashboardsDefaultIndex(ctx, tenantName, dataViewID); err != nil {
		return err
	}

	c.ensuredDataViews.Store(cacheKey, true)
	return nil
}

func (c *Client) setDashboardsDefaultIndex(ctx context.Context, tenantName, dataViewID string) error {
	body := dashboardsSettingValueRequest{
		Value: dataViewID,
	}
	if err := c.doDashboardsJSONInTenant(ctx, tenantName, http.MethodPost, "/api/opensearch-dashboards/settings/defaultIndex", body, nil, []int{http.StatusOK}); err != nil {
		return fmt.Errorf("set Dashboards default index for tenant %q: %w", tenantName, err)
	}
	return nil
}

func (c *Client) bootstrapDateStream(ctx context.Context, indexName, alias string) error {
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

	return c.doJSON(ctx, http.MethodPut, "/"+url.PathEscape(indexName), body, nil, []int{200, 201})
}

func (c *Client) attachISMPolicy(ctx context.Context, indexName, policyID string) error {
	body := map[string]any{
		"policy_id": policyID,
	}

	path := "/_plugins/_ism/add/" + url.PathEscape(indexName)
	return c.doJSON(ctx, http.MethodPost, path, body, nil, []int{200, 201})
}

func (c *Client) aliasExists(ctx context.Context, alias string) (bool, error) {
	req, err := c.newRequest(ctx, http.MethodHead, "/_alias/"+url.PathEscape(alias), nil)
	if err != nil {
		return false, err
	}

	resp, err := c.cfg.HTTPClient.Do(req)
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
			Path:       "/_alias/" + url.PathEscape(alias),
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.doJSONWithRequest(ctx, method, path, body, out, okStatuses, c.newRequest)
}

func (c *Client) doDashboardsJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.doJSONWithRequest(ctx, method, path, body, out, okStatuses, c.newDashboardsRequest)
}

func (c *Client) doDashboardsJSONInTenant(ctx context.Context, tenantName, method, path string, body any, out any, okStatuses []int) error {
	return c.doJSONWithRequest(ctx, method, path, body, out, okStatuses, func(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
		return c.newDashboardsRequestForTenant(ctx, tenantName, method, path, body)
	})
}

func (c *Client) doJSONWithRequest(ctx context.Context, method, path string, body any, out any, okStatuses []int, buildRequest func(context.Context, string, string, io.Reader) (*http.Request, error)) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}

	req, err := buildRequest(ctx, method, path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !containsStatus(okStatuses, resp.StatusCode) {
		b, _ := io.ReadAll(resp.Body)
		return &ResponseError{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.newRequestForBase(ctx, c.cfg.BaseURL, method, path, body, c.cfg.Username, c.cfg.Password, nil)
}

func (c *Client) newDashboardsRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.newDashboardsRequestForTenant(ctx, c.cfg.DashboardsTenant, method, path, body)
}

func (c *Client) newDashboardsRequestForTenant(ctx context.Context, tenantName, method, path string, body io.Reader) (*http.Request, error) {
	headers := map[string]string{
		"osd-xsrf": "true",
	}
	if tenantName != "" {
		headers["securitytenant"] = tenantName
	}

	return c.newRequestForBase(ctx, c.cfg.DashboardsURL, method, dashboardsAPIPath(path), body, c.cfg.DashboardsUsername, c.cfg.DashboardsPassword, headers)
}

func (c *Client) newRequestForBase(ctx context.Context, baseURL, method, path string, body io.Reader, username, password string, headers map[string]string) (*http.Request, error) {
	base := strings.TrimRight(baseURL, "/")
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, err
	}

	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

func isRetryableBootstrapConflict(err error) bool {
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

func isNotFoundResponse(err error) bool {
	var responseErr *ResponseError
	return errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound
}

func buildISMPolicy(minDocCount int) ismPolicy {
	return ismPolicy{
		Description:  "Generic rollover at 100M docs",
		DefaultState: "hot",
		States: []ismState{
			{
				Name: "hot",
				Actions: []ismAction{
					{
						Rollover: &ismRolloverAction{
							MinDocCount: minDocCount,
						},
					},
				},
				Transitions: []ismTransition{},
			},
		},
	}
}

func buildDataViewID(indexName string) string {
	return "gateway-index-pattern-" + indexName
}

func buildDataViewPattern(indexName string) string {
	return indexName + "-*"
}

func dashboardsAPIPath(path string) string {
	if path == "/dashboards" || strings.HasPrefix(path, "/dashboards/") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return "/dashboards" + path
	}
	return "/dashboards/" + path
}

func normalizeAccessByNamespace(access []Access) []Access {
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

func accessGroupNames(access []Access) []string {
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

func roleModeForAccess(access Access) string {
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

func buildGatewayRoleName(namespace, mode string) string {
	return "gateway_" + namespace + "_" + mode
}

func roleRequestForAccess(access Access) securityRoleRequest {
	mode := roleModeForAccess(access)

	clusterPermissions := []string{"cluster_composite_ops_ro", "indices_monitor"}
	if mode == "rw" || mode == "rwd" {
		clusterPermissions = []string{"cluster_composite_ops", "indices_monitor"}
	}
	clusterPermissions = append(clusterPermissions, "cluster:admin/opensearch/ql/datasources/read")

	return securityRoleRequest{
		ClusterPermissions: clusterPermissions,
		IndexPermissions: []securityIndexPermission{
			{
				IndexPatterns:  []string{buildDataViewPattern(access.Namespace)},
				AllowedActions: allowedActionsForAccess(mode),
			},
			{
				// Dashboards resolves wildcard patterns against every visible index name.
				IndexPatterns:  []string{"*"},
				AllowedActions: []string{"indices:admin/resolve/index"},
			},
		},
		TenantPermissions: []securityTenantPermission{
			{
				TenantPatterns: []string{access.Namespace},
				// Dashboards updates saved object metadata and defaultIndex even for read-only users.
				AllowedActions: []string{"kibana_all_write"},
			},
		},
	}
}

func isDashboardsIndexPatternFindRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if req.URL.Path != dashboardsAPIPath("/api/saved_objects/_find") {
		return false
	}

	for _, item := range req.URL.Query()["type"] {
		if item == "index-pattern" {
			return true
		}
	}
	return false
}

func matchesIndexPatternFindQuery(values url.Values, tenantName string) bool {
	search := strings.TrimSpace(strings.Trim(values.Get("search"), "*"))
	if search == "" {
		return true
	}

	title := buildDataViewPattern(tenantName)
	id := buildDataViewID(tenantName)
	return strings.Contains(title, search) || strings.Contains(id, search) || strings.Contains(tenantName, search)
}

func allowedActionsForAccess(mode string) []string {
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

func (s *sessionStore) Create(data sessionData) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessions == nil {
		s.sessions = make(map[string]sessionData)
	}

	now := time.Now()
	expiresAt := now.Add(sessionTTL)
	data.CreatedAt = now
	data.ExpiresAt = expiresAt

	for attempt := 0; attempt < 5; attempt++ {
		token, err := randomToken()
		if err != nil {
			return "", time.Time{}, err
		}
		if _, exists := s.sessions[token]; exists {
			continue
		}
		s.sessions[token] = data
		return token, expiresAt, nil
	}

	return "", time.Time{}, errors.New("failed to allocate unique session token")
}

func (s *sessionStore) Get(token string) (sessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return sessionData{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return sessionData{}, false
	}
	return session, true
}

func (s *sessionStore) Touch(token string) (sessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return sessionData{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return sessionData{}, false
	}

	session.ExpiresAt = time.Now().Add(sessionTTL)
	s.sessions[token] = session
	return session, true
}

func (s *sessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func buildBasicAuthorization(username, password string) string {
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + token
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func writeIngestAuthRequired(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="OpenSearchGateway ingest"`)
	writeErrorJSON(w, http.StatusUnauthorized, message)
}

func serveDemoPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, demoPageHTML)
}

func containsStatus(ok []int, code int) bool {
	for _, s := range ok {
		if s == code {
			return true
		}
	}
	return false
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func fatal(err error) {
	if err == nil {
		return
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		fmt.Fprintf(os.Stderr, "network error: %v\n", urlErr)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

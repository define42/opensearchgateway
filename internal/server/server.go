package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/define42/opensearchgateway/internal/authz"
	"github.com/define42/opensearchgateway/internal/ingest"
	ldappkg "github.com/define42/opensearchgateway/internal/ldap"
	"github.com/define42/opensearchgateway/internal/opensearch"
	"github.com/define42/opensearchgateway/internal/session"
)

const SessionCookieName = "opensearchgateway_session"

var (
	errIngestAuthRequired = errors.New("ingest authentication required")
	errIngestForbidden    = errors.New("ingest user is not allowed to write to this index")
)

type AuthenticateFunc func(string, string) (*authz.User, []authz.Access, error)

type Gateway struct {
	Client          *opensearch.Client
	Authenticate    AuthenticateFunc
	Sessions        *session.Store
	IngestAuthCache *ingest.AuthCache
}

type LoginPageData struct {
	Error    string
	Username string
}

type IngestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func New(client *opensearch.Client, authenticate AuthenticateFunc) *Gateway {
	if authenticate == nil {
		authenticate = func(username, password string) (*authz.User, []authz.Access, error) {
			return nil, nil, ldappkg.ErrInvalidCredentials
		}
	}

	return &Gateway{
		Client:          client,
		Authenticate:    authenticate,
		Sessions:        session.NewStore(),
		IngestAuthCache: ingest.NewAuthCache(),
	}
}

func (g *Gateway) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleRoot)
	mux.HandleFunc("/login", g.handleLogin)
	mux.HandleFunc("/logout", g.handleLogout)
	mux.HandleFunc("/dashboards", g.HandleDashboards)
	mux.HandleFunc("/dashboards/", g.HandleDashboards)
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
		if _, sessionData, ok := g.currentSession(r); ok && sessionData.ExpiresAt.After(time.Now()) {
			http.Redirect(w, r, "/dashboards/", http.StatusSeeOther)
			return
		}
		g.RenderLoginPage(w, http.StatusOK, LoginPageData{})
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
		g.Sessions.Delete(token)
	} else if cookie, err := r.Cookie(SessionCookieName); err == nil {
		g.Sessions.Delete(cookie.Value)
	}

	g.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (g *Gateway) HandleDashboards(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboards" && !strings.HasPrefix(r.URL.Path, "/dashboards/") {
		http.NotFound(w, r)
		return
	}

	token, sessionData, ok := g.currentSession(r)
	if !ok {
		g.clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	sessionData, ok = g.Sessions.Touch(token)
	if !ok {
		g.clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	g.setSessionCookie(w, r, token, sessionData.ExpiresAt)
	if err := g.proxyDashboards(w, r, sessionData); err != nil {
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
		g.RenderLoginPage(w, http.StatusBadGateway, LoginPageData{Error: "failed to read login form"})
		return
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		g.RenderLoginPage(w, http.StatusUnauthorized, LoginPageData{
			Error:    "username and password are required",
			Username: username,
		})
		return
	}

	user, access, err := g.Authenticate(username, password)
	if err != nil {
		status, message := loginErrorResponse(err)
		g.RenderLoginPage(w, status, LoginPageData{
			Error:    message,
			Username: username,
		})
		return
	}

	namespaces, err := g.Client.ProvisionLoginUser(r.Context(), username, password, access)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, opensearch.ErrReservedInternalUser) {
			status = http.StatusForbidden
		}
		g.RenderLoginPage(w, status, LoginPageData{
			Error:    err.Error(),
			Username: username,
		})
		return
	}

	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		g.Sessions.Delete(cookie.Value)
	}

	token, expiresAt, err := g.Sessions.Create(session.Data{
		User:       user,
		Access:     access,
		Namespaces: namespaces,
		AuthHeader: BuildBasicAuthorization(username, password),
		CreatedAt:  time.Now(),
	})
	if err != nil {
		g.RenderLoginPage(w, http.StatusBadGateway, LoginPageData{
			Error:    "failed to create login session",
			Username: username,
		})
		return
	}

	g.setSessionCookie(w, r, token, expiresAt)
	http.Redirect(w, r, "/dashboards/", http.StatusSeeOther)
}

func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	indexName, err := ingest.ParsePath(r.URL.Path)
	if err != nil {
		if errors.Is(err, ingest.ErrRouteNotFound) {
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
		case errors.Is(err, errIngestAuthRequired), errors.Is(err, ldappkg.ErrInvalidCredentials), errors.Is(err, ldappkg.ErrUserNotFound):
			writeIngestAuthRequired(w, "LDAP username and password are required for ingest")
		case errors.Is(err, ldappkg.ErrUnauthorized), errors.Is(err, errIngestForbidden):
			writeErrorJSON(w, http.StatusForbidden, "your LDAP account is not allowed to ingest into this index")
		default:
			writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("LDAP authentication failed: %v", err))
		}
		return
	}

	mediaType := strings.TrimSpace(r.Header.Get("Content-Type"))
	contentType, _, err := mimeParse(mediaType)
	if err != nil || contentType != "application/json" {
		writeErrorJSON(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}

	document, err := ingest.DecodeJSONObject(r.Body)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	eventTime, err := ingest.ParseEventTime(document)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	writeAlias := ingest.BuildWriteAlias(indexName, eventTime)
	firstIndex := ingest.BuildFirstBackingIndex(writeAlias)
	if len(writeAlias) > ingest.MaxIndexNameBytes || len(firstIndex) > ingest.MaxIndexNameBytes {
		writeErrorJSON(w, http.StatusBadRequest, "generated alias or backing index name exceeds OpenSearch limits")
		return
	}

	document["event_time"] = eventTime.UTC().Format(time.RFC3339)

	if err := g.Client.EnsureDashboardDataView(r.Context(), indexName); err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Dashboards setup failed: %v", err))
		return
	}

	bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), writeAlias)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("OpenSearch bootstrap failed: %v", err))
		return
	}

	indexed, err := g.Client.IndexDocument(r.Context(), writeAlias, document)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("OpenSearch ingest failed: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, IngestResponse{
		Result:       indexed.Result,
		WriteAlias:   writeAlias,
		DocumentID:   indexed.ID,
		Bootstrapped: bootstrapped,
	})
}

func (g *Gateway) RenderLoginPage(w http.ResponseWriter, status int, data LoginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := loginPageTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
	}
}

func loginErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, ldappkg.ErrInvalidCredentials), errors.Is(err, ldappkg.ErrUserNotFound):
		return http.StatusUnauthorized, "invalid username or password"
	case errors.Is(err, ldappkg.ErrUnauthorized):
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
	if !authz.HasIngestWriteAccess(access, indexName) {
		return errIngestForbidden
	}
	return nil
}

func (g *Gateway) ingestAccess(r *http.Request) ([]authz.Access, error) {
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
		username, password, ok := r.BasicAuth()
		if !ok || strings.TrimSpace(username) == "" || password == "" {
			return nil, errIngestAuthRequired
		}

		username = strings.TrimSpace(username)
		_, access, _, err := g.IngestAuthCache.Resolve(ingest.AuthCacheKey(username, password), func() (string, []authz.Access, error) {
			user, access, err := g.Authenticate(username, password)
			if err != nil {
				return "", nil, err
			}

			cachedUsername := username
			if user != nil && strings.TrimSpace(user.Name) != "" {
				cachedUsername = strings.TrimSpace(user.Name)
			}
			return cachedUsername, access, nil
		})
		if err != nil {
			return nil, err
		}
		return access, nil
	}

	if _, sessionData, ok := g.currentSession(r); ok {
		return sessionData.Access, nil
	}

	return nil, errIngestAuthRequired
}

func (g *Gateway) currentSession(r *http.Request) (string, session.Data, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", session.Data{}, false
	}

	sessionData, ok := g.Sessions.Get(cookie.Value)
	if !ok {
		return cookie.Value, session.Data{}, false
	}
	return cookie.Value, sessionData, true
}

func (g *Gateway) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
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
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func BuildBasicAuthorization(username, password string) string {
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + token
}

func ForwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func SessionHasNamespace(data session.Data, tenantName string) bool {
	for _, namespace := range data.Namespaces {
		if strings.TrimSpace(namespace) == tenantName {
			return true
		}
	}
	return false
}

func sessionDefaultTenant(data session.Data) string {
	if len(data.Namespaces) != 1 {
		return ""
	}
	return strings.TrimSpace(data.Namespaces[0])
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}

func writeIngestAuthRequired(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="OpenSearchGateway ingest"`)
	writeErrorJSON(w, http.StatusUnauthorized, message)
}

func mimeParse(value string) (string, map[string]string, error) { return mime.ParseMediaType(value) }

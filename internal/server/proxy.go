package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/define42/opensearchgateway/internal/session"
)

func (g *Gateway) proxyDashboards(w http.ResponseWriter, r *http.Request, sessionData session.Data) error {
	target, err := url.Parse(g.Client.Config.DashboardsURL)
	if err != nil {
		return fmt.Errorf("invalid Dashboards URL: %w", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", ForwardedProto(pr.In))
		},
		ErrorHandler: func(proxyWriter http.ResponseWriter, _ *http.Request, proxyErr error) {
			writeErrorJSON(proxyWriter, http.StatusBadGateway, fmt.Sprintf("Dashboards proxy failed: %v", proxyErr))
		},
	}

	proxy.ServeHTTP(w, r)
	return nil
}

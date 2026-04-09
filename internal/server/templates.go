package server

import (
	_ "embed"
	"html/template"
	"io"
	"net/http"
)

//go:embed templates/login.html
var loginPageHTML string

//go:embed templates/demo.html
var demoPageHTML string

func loginTemplate() *template.Template {
	return template.Must(template.New("login").Parse(loginPageHTML))
}

func serveDemoPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, demoPageHTML)
}

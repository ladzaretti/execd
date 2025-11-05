package main

import (
	"context"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates
var tmplFS embed.FS

type Exec struct {
	ID      string
	Command string
	Status  string
}

func listExecs(_ context.Context) []Exec {
	return []Exec{
		{ID: "1", Command: "uptime", Status: "done"},
		{ID: "2", Command: "ls -la", Status: "running"},
	}
}

type renderer struct{ t *template.Template }

func newRenderer() *renderer {
	t := template.Must(
		template.New("root").
			Funcs(template.FuncMap{}).
			ParseFS(
				tmplFS,
				"templates/layouts/*.tmpl",
				"templates/pages/*.tmpl",
				"templates/fragments/*.tmpl",
			))

	return &renderer{t: t}
}

func (r *renderer) write(w http.ResponseWriter, name string, data any) {
	t := r.t.Lookup(name)
	if t == nil {
		http.Error(w, "template not found: "+name, http.StatusNotFound)
		return
	}

	if err := t.Execute(w, data); err != nil {
		http.Error(w, "template exec error: "+err.Error(), http.StatusInternalServerError)
	}
}

func newUIHandler(rr *renderer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		rr.write(w, "pages/execs.tmpl", nil)
	})
}

func newHXHandler(rr *renderer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := struct{ Execs []Exec }{Execs: listExecs(r.Context())}
		rr.write(w, "fragments/exec_table.tmpl", data)
	})
}

func newUIRoutes(rr *renderer, sess *sessions, password string) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /", chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/execs", http.StatusFound)
		}),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /execs", chain(
		newUIHandler(rr),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	return mux
}

func newHXRoutes(rr *renderer, sess *sessions, password string) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /execs", chain(
		newHXHandler(rr),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	return mux
}

package templates

import (
	"embed"
	"html/template"
	"io"
	"log"
	"net/http"
	"path"
)

//go:embed *.html *.css *.js
var embeddedFS embed.FS

// ServeStatic serves static files from the embedded filesystem
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	// Extract filename from path (e.g., /static/style.css -> style.css)
	filename := path.Base(r.URL.Path)
	
	data, err := embeddedFS.ReadFile(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	// Set content type based on file extension
	switch path.Ext(filename) {
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	}
	
	io.WriteString(w, string(data))
}

// LoadTemplate loads a template from embedded files with custom functions
func LoadTemplate(funcMap template.FuncMap, names ...string) *template.Template {
	if funcMap == nil {
		funcMap = template.FuncMap{}
	}

	tmpl := template.New("").Funcs(funcMap)
	for _, name := range names {
		data, err := embeddedFS.ReadFile(name + ".html")
		if err != nil {
			log.Fatalf("Failed to load embedded template %s: %v", name, err)
		}
		t, err := tmpl.New(name).Parse(string(data))
		if err != nil {
			log.Fatalf("Failed to parse template %s: %v", name, err)
		}
		tmpl = t
	}

	return tmpl
}

// LoadSimpleTemplate loads a template without custom functions
func LoadSimpleTemplate(names ...string) *template.Template {
	return LoadTemplate(nil, names...)
}

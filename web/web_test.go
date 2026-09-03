package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmbeddedTemplatesParse(t *testing.T) {
	server := NewServer()
	_, err := server.getHtmlTemplate(template.FuncMap{
		"i18n": func(key string, _ ...string) (string, error) { return key, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedHTTPSRedirect(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:54321/xui/?page=1", nil)
	managedHTTPSRedirect("panel.example.com", 8443).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "https://panel.example.com:8443/xui/?page=1" {
		t.Fatalf("location = %q", location)
	}
}

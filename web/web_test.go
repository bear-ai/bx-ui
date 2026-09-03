package web

import (
	"html/template"
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

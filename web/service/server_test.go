package service

import (
	"reflect"
	"testing"
)

func TestParseXrayVersions(t *testing.T) {
	data := []byte(`[
		{"name":"v26.7.28"},
		{"name":"not-a-release"},
		{"name":"v26.7.11"},
		{"name":"v26.7.28"},
		{"name":"26.6.27"}
	]`)
	want := []string{"v26.7.28", "v26.7.11"}
	got, err := parseXrayVersions(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected versions: got %v, want %v", got, want)
	}
}

func TestParseXrayVersionsRejectsInvalidJSON(t *testing.T) {
	if _, err := parseXrayVersions([]byte(`{"name":`)); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

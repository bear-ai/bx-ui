package entity

import "testing"

func TestServiceDomainName(t *testing.T) {
	domain, err := serviceDomainName("Panel.Example.COM.")
	if err != nil || domain != "panel.example.com" {
		t.Fatalf("unexpected normalized domain: %q, %v", domain, err)
	}
	for _, value := range []string{"localhost", "127.0.0.1", "*.example.com", "bad..example"} {
		if _, err := serviceDomainName(value); err == nil {
			t.Fatalf("invalid domain %q was accepted", value)
		}
	}
}

func TestManagedHTTPSPortValidation(t *testing.T) {
	for _, httpsPort := range []int{443, 80} {
		setting := &AllSetting{WebPort: 443, WebHTTPSPort: httpsPort, WebDomain: "panel.example.com"}
		if err := setting.CheckValid(); err == nil {
			t.Fatalf("invalid HTTPS port %d was accepted", httpsPort)
		}
	}
}

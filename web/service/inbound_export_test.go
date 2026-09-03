package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"x-ui/database/model"
)

func exportInbound(protocol model.Protocol, settings, stream string) *model.Inbound {
	return &model.Inbound{
		Port:           443,
		Protocol:       protocol,
		Settings:       settings,
		StreamSettings: stream,
	}
}

func validateExportedXrayConfig(t *testing.T, data []byte) {
	t.Helper()
	var config struct {
		Inbounds  []map[string]interface{} `json:"inbounds"`
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("exported config is invalid JSON: %v\n%s", err, data)
	}
	if len(config.Inbounds) != 1 || config.Inbounds[0]["protocol"] != "socks" {
		t.Fatalf("exported config does not contain the local SOCKS inbound: %s", data)
	}
	if len(config.Outbounds) != 2 || config.Outbounds[0]["tag"] != "proxy" || config.Outbounds[1]["protocol"] != "freedom" {
		t.Fatalf("exported config does not contain the expected outbounds: %s", data)
	}
}

func TestBuildClientConfigSupportedProtocols(t *testing.T) {
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name    string
		inbound *model.Inbound
	}{
		{
			name: "vmess",
			inbound: exportInbound(model.VMess,
				`{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto"}]}`,
				`{"network":"tcp","security":"none","tcpSettings":{"acceptProxyProtocol":true}}`),
		},
		{
			name: "vless reality",
			inbound: exportInbound(model.VLESS,
				`{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}],"decryption":"none","encryption":"none"}`,
				`{"network":"tcp","security":"reality","realitySettings":{"target":"example.com:443","serverNames":["example.com"],"privateKey":"must-not-export","publicKey":"`+publicKey+`","shortIds":["0123456789abcdef"],"fingerprint":"chrome","spiderX":"/"}}`),
		},
		{
			name: "trojan tls",
			inbound: exportInbound(model.Trojan,
				`{"clients":[{"password":"long-trojan-password"}]}`,
				`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":["h2"],"certificates":[{"certificateFile":"server.crt","keyFile":"server.key"}]}}`),
		},
		{
			name: "shadowsocks",
			inbound: exportInbound(model.Shadowsocks,
				`{"method":"aes-256-gcm","password":"long-shadowsocks-password","network":"tcp,udp"}`,
				`{"network":"tcp","security":"none"}`),
		},
		{
			name: "hysteria",
			inbound: exportInbound(model.Protocol("hysteria"),
				`{"version":2,"clients":[{"auth":"hysteria-password"}]}`,
				`{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"certificateFile":"server.crt","keyFile":"server.key"}]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60,"masquerade":{"type":"file","dir":"/srv/private"}}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := BuildClientConfig(test.inbound, "203.0.113.9")
			if err != nil {
				t.Fatal(err)
			}
			validateExportedXrayConfig(t, data)
			text := string(data)
			for _, secretField := range []string{"privateKey", "certificateFile", "keyFile", "certificates", "acceptProxyProtocol", "masquerade", "/srv/private"} {
				if strings.Contains(text, `"`+secretField+`"`) {
					t.Fatalf("server-only field %q leaked into client config", secretField)
				}
			}
		})
	}
}

func TestBuildClientConfigRealityAndHysteriaFields(t *testing.T) {
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	realityInbound := exportInbound(model.VLESS,
		`{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"encryption":"none"}`,
		`{"network":"tcp","security":"reality","realitySettings":{"serverNames":["sni.example"],"publicKey":"`+publicKey+`","shortIds":["abcd"]}}`)
	data, err := BuildClientConfig(realityInbound, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	outbound := config["outbounds"].([]interface{})[0].(map[string]interface{})
	stream := outbound["streamSettings"].(map[string]interface{})
	reality := stream["realitySettings"].(map[string]interface{})
	if reality["serverName"] != "sni.example" || reality["publicKey"] != publicKey || reality["shortId"] != "abcd" {
		t.Fatalf("incorrect REALITY client settings: %#v", reality)
	}

	hysteriaInbound := exportInbound(model.Protocol("hysteria"),
		`{"clients":[{"auth":"expected-auth"}]}`,
		`{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com"},"hysteriaSettings":{"version":2}}`)
	data, err = BuildClientConfig(hysteriaInbound, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"auth": "expected-auth"`) {
		t.Fatal("Hysteria client auth was not copied to transport settings")
	}
}

func TestBuildClientConfigRejectsInvalidInput(t *testing.T) {
	valid := exportInbound(model.VMess,
		`{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}`,
		`{"network":"tcp","security":"none"}`)
	for _, address := range []string{"", "https://example.com", "user@example.com", "example.com:443", "-bad.example"} {
		if _, err := BuildClientConfig(valid, address); !errors.Is(err, ErrClientExportInvalid) {
			t.Fatalf("address %q: expected invalid export error, got %v", address, err)
		}
	}
	unsupported := exportInbound(model.Http, `{}`, `{}`)
	if _, err := BuildClientConfig(unsupported, "example.com"); !errors.Is(err, ErrClientExportUnsupported) {
		t.Fatalf("expected unsupported protocol error, got %v", err)
	}
	missingCredential := exportInbound(model.VLESS, `{"clients":[]}`, `{}`)
	if _, err := BuildClientConfig(missingCredential, "example.com"); !errors.Is(err, ErrClientExportInvalid) {
		t.Fatalf("expected invalid export error, got %v", err)
	}
	missingRealityKey := exportInbound(model.VLESS,
		`{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"encryption":"none"}`,
		`{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"]}}`)
	if _, err := BuildClientConfig(missingRealityKey, "example.com"); !errors.Is(err, ErrClientExportInvalid) {
		t.Fatalf("expected missing REALITY key error, got %v", err)
	}
}

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"

	"x-ui/database/model"
)

var (
	ErrClientExportUnsupported = errors.New("当前协议不支持客户端 JSON 导出")
	ErrClientExportInvalid     = errors.New("入站配置无法导出")
)

// NormalizeExportAddress accepts an IP address or an ASCII DNS name. The value
// becomes connection data in the downloaded client config, so do not silently
// accept URL syntax, credentials, ports, or control characters.
func NormalizeExportAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	if value == "" || len(value) > 253 {
		return "", fmt.Errorf("%w: 服务器地址无效", ErrClientExportInvalid)
	}
	if net.ParseIP(value) != nil {
		return value, nil
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: 服务器地址无效", ErrClientExportInvalid)
		}
		for _, r := range label {
			if r > unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-') {
				return "", fmt.Errorf("%w: 服务器地址无效", ErrClientExportInvalid)
			}
		}
	}
	return value, nil
}

func decodeExportObject(raw, field string) (map[string]interface{}, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "{}"
	}
	var value map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, fmt.Errorf("%w: %s 不是有效 JSON", ErrClientExportInvalid, field)
	}
	return value, nil
}

func exportString(value map[string]interface{}, key string) string {
	text, _ := value[key].(string)
	return text
}

func firstExportObject(value map[string]interface{}, key string) (map[string]interface{}, error) {
	items, ok := value[key].([]interface{})
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("%w: %s 中没有客户端凭据", ErrClientExportInvalid, key)
	}
	item, ok := items[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s 客户端凭据格式无效", ErrClientExportInvalid, key)
	}
	return item, nil
}

func requireExportString(value map[string]interface{}, key string) (string, error) {
	text := exportString(value, key)
	if text == "" {
		return "", fmt.Errorf("%w: 缺少 %s", ErrClientExportInvalid, key)
	}
	return text, nil
}

func copyExportObject(value interface{}) map[string]interface{} {
	object, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	copy := make(map[string]interface{}, len(object))
	for key, item := range object {
		copy[key] = item
	}
	delete(copy, "acceptProxyProtocol")
	return copy
}

func clientStreamSettings(stream map[string]interface{}, address, hysteriaAuth string) (map[string]interface{}, error) {
	network := exportString(stream, "network")
	if network == "" {
		network = "tcp"
	}
	security := exportString(stream, "security")
	if security == "" {
		security = "none"
	} else if security == "xtls" {
		security = "tls"
	}

	result := map[string]interface{}{
		"network":  network,
		"security": security,
	}
	transportKey := map[string]string{
		"tcp":         "tcpSettings",
		"raw":         "rawSettings",
		"kcp":         "kcpSettings",
		"mkcp":        "kcpSettings",
		"ws":          "wsSettings",
		"websocket":   "wsSettings",
		"http":        "httpSettings",
		"quic":        "quicSettings",
		"grpc":        "grpcSettings",
		"httpupgrade": "httpupgradeSettings",
		"xhttp":       "xhttpSettings",
		"splithttp":   "splithttpSettings",
		"hysteria":    "hysteriaSettings",
	}[strings.ToLower(network)]
	if transportKey != "" {
		transport := copyExportObject(stream[transportKey])
		if network == "hysteria" && hysteriaAuth != "" {
			udpIdleTimeout := interface{}(float64(60))
			if transport != nil && transport["udpIdleTimeout"] != nil {
				udpIdleTimeout = transport["udpIdleTimeout"]
			}
			transport = map[string]interface{}{
				"version":        2,
				"auth":           hysteriaAuth,
				"udpIdleTimeout": udpIdleTimeout,
			}
		}
		if transport != nil {
			result[transportKey] = transport
		}
	}

	switch security {
	case "tls":
		tlsSettings := copyExportObject(stream["tlsSettings"])
		clientTLS := map[string]interface{}{"allowInsecure": false}
		if tlsSettings != nil {
			if serverName := exportString(tlsSettings, "serverName"); serverName != "" {
				clientTLS["serverName"] = serverName
			}
			if alpn, ok := tlsSettings["alpn"].([]interface{}); ok && len(alpn) > 0 {
				clientTLS["alpn"] = alpn
			}
		}
		result["tlsSettings"] = clientTLS
	case "reality":
		reality := copyExportObject(stream["realitySettings"])
		if reality == nil {
			reality = map[string]interface{}{}
		}
		serverName := exportString(reality, "serverName")
		if serverName == "" {
			if names, ok := reality["serverNames"].([]interface{}); ok && len(names) > 0 {
				serverName, _ = names[0].(string)
			}
		}
		if serverName == "" {
			serverName = address
		}
		publicKey := exportString(reality, "publicKey")
		if publicKey == "" {
			publicKey = exportString(reality, "password")
		}
		if publicKey == "" {
			return nil, fmt.Errorf("%w: REALITY 缺少客户端公钥", ErrClientExportInvalid)
		}
		shortID := exportString(reality, "shortId")
		if shortID == "" {
			if ids, ok := reality["shortIds"].([]interface{}); ok && len(ids) > 0 {
				shortID, _ = ids[0].(string)
			}
		}
		clientReality := map[string]interface{}{
			"serverName":  serverName,
			"fingerprint": exportString(reality, "fingerprint"),
			"publicKey":   publicKey,
			"shortId":     shortID,
			"spiderX":     exportString(reality, "spiderX"),
		}
		if clientReality["fingerprint"] == "" {
			clientReality["fingerprint"] = "chrome"
		}
		if clientReality["spiderX"] == "" {
			clientReality["spiderX"] = "/"
		}
		result["realitySettings"] = clientReality
	case "none":
	default:
		return nil, fmt.Errorf("%w: 不支持的传输安全类型 %s", ErrClientExportInvalid, security)
	}
	return result, nil
}

func buildClientOutbound(inbound *model.Inbound, address string) (map[string]interface{}, error) {
	settings, err := decodeExportObject(inbound.Settings, "settings")
	if err != nil {
		return nil, err
	}
	stream, err := decodeExportObject(inbound.StreamSettings, "streamSettings")
	if err != nil {
		return nil, err
	}

	protocol := strings.ToLower(string(inbound.Protocol))
	outboundSettings := map[string]interface{}{
		"address": address,
		"port":    inbound.Port,
	}
	hysteriaAuth := ""
	switch protocol {
	case "vmess":
		client, err := firstExportObject(settings, "clients")
		if err != nil {
			return nil, err
		}
		id, err := requireExportString(client, "id")
		if err != nil {
			return nil, err
		}
		outboundSettings["id"] = id
		outboundSettings["security"] = exportString(client, "security")
		if outboundSettings["security"] == "" {
			outboundSettings["security"] = "auto"
		}
	case "vless":
		client, err := firstExportObject(settings, "clients")
		if err != nil {
			return nil, err
		}
		id, err := requireExportString(client, "id")
		if err != nil {
			return nil, err
		}
		outboundSettings["id"] = id
		outboundSettings["encryption"] = exportString(settings, "encryption")
		if outboundSettings["encryption"] == "" {
			outboundSettings["encryption"] = "none"
		}
		if flow := exportString(client, "flow"); flow != "" {
			outboundSettings["flow"] = flow
		}
	case "trojan":
		client, err := firstExportObject(settings, "clients")
		if err != nil {
			return nil, err
		}
		password, err := requireExportString(client, "password")
		if err != nil {
			return nil, err
		}
		outboundSettings["password"] = password
	case "shadowsocks":
		method, err := requireExportString(settings, "method")
		if err != nil {
			return nil, err
		}
		password, err := requireExportString(settings, "password")
		if err != nil {
			return nil, err
		}
		outboundSettings["method"] = method
		outboundSettings["password"] = password
	case "hysteria":
		client, err := firstExportObject(settings, "clients")
		if err != nil {
			return nil, err
		}
		hysteriaAuth, err = requireExportString(client, "auth")
		if err != nil {
			return nil, err
		}
		outboundSettings["version"] = 2
	default:
		return nil, fmt.Errorf("%w: %s", ErrClientExportUnsupported, protocol)
	}

	clientStream, err := clientStreamSettings(stream, address, hysteriaAuth)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"tag":            "proxy",
		"protocol":       protocol,
		"settings":       outboundSettings,
		"streamSettings": clientStream,
	}, nil
}

// BuildClientConfig creates a complete Xray client configuration. Only the
// first credential is exported, matching the panel's existing share-link and
// QR-code behavior.
func BuildClientConfig(inbound *model.Inbound, address string) ([]byte, error) {
	address, err := NormalizeExportAddress(address)
	if err != nil {
		return nil, err
	}
	if inbound == nil || inbound.Port < 1 || inbound.Port > 65535 {
		return nil, fmt.Errorf("%w: 端口无效", ErrClientExportInvalid)
	}
	outbound, err := buildClientOutbound(inbound, address)
	if err != nil {
		return nil, err
	}
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "socks-in",
				"listen":   "127.0.0.1",
				"port":     10808,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
			},
		},
	}
	return json.MarshalIndent(config, "", "  ")
}

func (s *InboundService) ExportClientConfig(id, userID int, address string) ([]byte, error) {
	inbound, err := s.GetInboundForUser(id, userID)
	if err != nil {
		return nil, err
	}
	return BuildClientConfig(inbound, address)
}

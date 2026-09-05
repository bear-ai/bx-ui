package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"x-ui/util/json_util"
)

const configTestTimeout = 15 * time.Second
const configTestOutputLimit = 16 * 1024

// cappedOutput always consumes the child's output without allowing an invalid
// configuration (or an incompatible executable) to exhaust panel memory.
type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := configTestOutputLimit - b.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return n, nil
}

// ValidateConfig checks with the installed core, not only the core version used
// to compile the panel. It must finish before saving settings or stopping Xray.
func ValidateConfig(config *Config) error {
	return validateConfig(config, GetBinaryPath(), filepath.Dir(GetConfigPath()), CheckTUNSupport, configTestTimeout)
}

func validateConfig(config *Config, binary, tempDir string, checkTUN func() error, timeout time.Duration) error {
	if config == nil {
		return errors.New("Xray 配置不能为空")
	}
	copyConfig := *config
	copyConfig.InboundConfigs = append([]InboundConfig(nil), config.InboundConfigs...)
	names := map[string]bool{}
	hasTUN := false
	for index, inbound := range copyConfig.InboundConfigs {
		if !strings.EqualFold(inbound.Protocol, "tun") {
			continue
		}
		name, err := validateTUNSettings(inbound.Settings)
		if err != nil {
			return err
		}
		if names[name] {
			return errors.New("多个 TUN 入站不能使用相同的接口名称")
		}
		names[name] = true
		hasTUN = true
		// Xray's -test constructs TUN devices before exiting. Never pass a real
		// TUN configuration to that command while the old core is still running.
		// Retain the tag and receiver settings so routing and stream validation
		// still apply, but use a harmless protocol for this phase.
		inbound.Protocol = "dokodemo-door"
		inbound.Listen = json_util.RawMessage(`"127.0.0.1"`)
		inbound.Port = 1
		inbound.Settings = json_util.RawMessage(`{"address":"127.0.0.1","network":"tcp"}`)
		copyConfig.InboundConfigs[index] = inbound
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if hasTUN {
		if err := checkTUN(); err != nil {
			return err
		}
		if err := testTUNLoader(ctx, binary, tempDir); err != nil {
			return err
		}
	}
	_, err := testConfig(ctx, binary, tempDir, &copyConfig)
	return err
}

func validateTUNSettings(raw []byte) (string, error) {
	var settings struct {
		Name      string `json:"name"`
		MTU       uint32 `json:"MTU"`
		UserLevel uint32 `json:"userLevel"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return "", errors.New("TUN 设置不是有效的 JSON，name 必须为字符串，MTU 和 userLevel 必须为非负整数")
	}
	name := settings.Name
	if name == "" {
		name = "xray0"
	}
	if len(name) > 15 || name == "." || name == ".." || strings.ContainsAny(name, "/:\x00") || strings.ContainsFunc(name, unicode.IsSpace) {
		return "", errors.New("TUN 接口名称须为 1–15 字节，不能包含空白、斜杠或冒号")
	}
	if settings.MTU != 0 && (settings.MTU < 576 || settings.MTU > 65535) {
		return "", errors.New("TUN MTU 须为 576–65535，或使用 0 采用默认值 1500")
	}
	return name, nil
}

func testTUNLoader(ctx context.Context, binary, tempDir string) error {
	// A deliberately wrong JSON type fails inside the installed core's TUN
	// loader, before core.New or a device constructor can run. Old cores that
	// do not register TUN produce a different error and are rejected safely.
	probe := &Config{InboundConfigs: []InboundConfig{{Protocol: "tun", Port: 1,
		Settings: json_util.RawMessage(`{"MTU":"bx-ui-tun-support-probe"}`)}}}
	output, err := testConfig(ctx, binary, tempDir, probe)
	if err != nil && strings.Contains(output, "cannot unmarshal string") && strings.Contains(output, "TunConfig.MTU") {
		return nil
	}
	if ctx.Err() != nil {
		return errors.New("Xray 配置检查超时，原配置未更改")
	}
	return errors.New("当前 Xray 内核未通过 TUN 支持检查，请先切换到支持 TUN 的官方内核版本（v26.3.27 或更新版本）")
}

func testConfig(ctx context.Context, binary, tempDir string, config *Config) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", errors.New("Xray 配置 JSON 无效，请检查入站和传输设置")
	}
	file, err := os.CreateTemp(tempDir, ".bx-ui-config-test-*.json")
	if err != nil {
		return "", errors.New("无法创建 Xray 预检配置，请检查 bin 目录写入权限")
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", errors.New("无法写入 Xray 预检配置")
	}
	if err := file.Close(); err != nil {
		return "", errors.New("无法关闭 Xray 预检配置文件")
	}
	// #nosec G204 -- binary is the locally installed Xray executable, not user input.
	cmd := exec.CommandContext(ctx, binary, "run", "-test", "-c", file.Name())
	cmd.Env = coreEnvironment()
	cmd.WaitDelay = time.Second
	output := &cappedOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run()
	if ctx.Err() != nil {
		return output.String(), errors.New("Xray 配置检查超时，原配置未更改")
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return output.String(), errors.New("无法执行 Xray 内核，请检查内核是否已安装及执行权限")
		}
		// Core errors may include passwords, private keys or the full settings.
		// Do not return or log the raw child output.
		return output.String(), errors.New("Xray 配置预检失败，请检查协议、传输参数、TLS 证书及当前内核兼容性（敏感错误内容已隐藏）")
	}
	return output.String(), nil
}

package xray

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"x-ui/util/common"

	"github.com/Workiva/go-datastructures/queue"
	statsservice "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var trafficRegex = regexp.MustCompile("(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)")

func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath() string {
	return "bin/" + GetBinaryName()
}

func GetConfigPath() string {
	return "bin/config.json"
}

func GetGeositePath() string {
	return "bin/geosite.dat"
}

func GetGeoipPath() string {
	return "bin/geoip.dat"
}

// Only the panel-generated configuration may be loaded. Xray otherwise merges
// an inherited configuration directory even when an explicit -c is supplied.
// The same environment is used for validation and the real running process.
func coreEnvironment() []string {
	environment := os.Environ()
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if name == "XRAY_LOCATION_CONFDIR" || name == "xray.location.confdir" {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func stopProcess(p *Process) {
	_ = p.Stop()
}

type Process struct {
	*process
}

func NewProcess(xrayConfig *Config) *Process {
	p := &Process{newProcess(xrayConfig)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

type process struct {
	stateMu sync.RWMutex
	running atomic.Bool
	cmd     *exec.Cmd
	done    chan struct{}

	version string
	apiPort int

	config  *Config
	lines   *queue.Queue
	exitErr error
}

func newProcess(config *Config) *process {
	return &process{
		version: "Unknown",
		config:  config,
		lines:   queue.New(100),
	}
}

func (p *process) IsRunning() bool {
	return p.running.Load()
}

func (p *process) GetErr() error {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.exitErr
}

func (p *process) GetResult() string {
	exitErr := p.GetErr()
	if p.lines.Empty() && exitErr != nil {
		return exitErr.Error()
	}
	items, _ := p.lines.TakeUntil(func(item interface{}) bool {
		return true
	})
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, item.(string))
	}
	return strings.Join(lines, "\n")
}

func (p *process) GetVersion() string {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.version
}

func (p *Process) GetAPIPort() int {
	return p.apiPort
}

func (p *Process) GetConfig() *Config {
	return p.config
}

func (p *process) refreshAPIPort() {
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			p.apiPort = inbound.Port
			break
		}
	}
}

func (p *process) refreshVersion() {
	p.refreshVersionFrom(GetBinaryPath())
}

func (p *process) refreshVersionFrom(binary string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- the executable path and argument are application constants.
	cmd := exec.CommandContext(ctx, binary, "-version")
	cmd.Env = coreEnvironment()
	cmd.WaitDelay = time.Second
	output := &cappedOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	data := output.Bytes()
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if err != nil {
		p.version = "Unknown"
	} else {
		datas := bytes.Split(data, []byte(" "))
		if len(datas) <= 1 {
			p.version = "Unknown"
		} else {
			p.version = string(datas[1])
		}
	}
}

func (p *process) Start() (err error) {
	return p.start(GetBinaryPath(), GetConfigPath())
}

func (p *process) start(binary, configPath string) (err error) {
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			p.stateMu.Lock()
			p.exitErr = err
			p.stateMu.Unlock()
		}
	}()

	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return common.NewErrorf("生成 xray 配置文件失败: %v", err)
	}
	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		return common.NewErrorf("写入配置文件失败: %v", err)
	}
	if err = os.Chmod(configPath, 0600); err != nil {
		return common.NewErrorf("设置 xray 配置文件权限失败: %v", err)
	}

	// #nosec G204 -- the executable and config paths are application constants.
	cmd := exec.Command(binary, "-c", configPath)
	cmd.Env = coreEnvironment()
	done := make(chan struct{})
	p.stateMu.Lock()
	p.cmd = cmd
	p.done = done
	p.exitErr = nil
	p.stateMu.Unlock()

	stdReader, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	errReader, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			common.Recover("")
			_ = stdReader.Close()
		}()
		reader := bufio.NewReaderSize(stdReader, 8192)
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				return
			}
			if p.lines.Len() >= 100 {
				_, _ = p.lines.Get(1)
			}
			_ = p.lines.Put(string(line))
		}
	}()

	go func() {
		defer func() {
			common.Recover("")
			_ = errReader.Close()
		}()
		reader := bufio.NewReaderSize(errReader, 8192)
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				return
			}
			if p.lines.Len() >= 100 {
				_, _ = p.lines.Get(1)
			}
			_ = p.lines.Put(string(line))
		}
	}()

	p.refreshVersionFrom(binary)
	p.refreshAPIPort()
	if err = cmd.Start(); err != nil {
		return err
	}
	p.running.Store(true)
	go func() {
		defer close(done)
		err := cmd.Wait()
		p.stateMu.Lock()
		if err != nil {
			p.exitErr = err
		}
		p.stateMu.Unlock()
		p.running.Store(false)
	}()
	// Most constructor, bind and permission failures occur immediately. Wait
	// briefly so a failed replacement can restore the previous process rather
	// than reporting success merely because exec.Start succeeded.
	select {
	case <-done:
		return errors.New("Xray 启动后立即退出，请检查配置、端口占用及系统权限")
	case <-time.After(time.Second):
		return nil
	}
}

func (p *process) Stop() error {
	if !p.IsRunning() {
		return errors.New("xray is not running")
	}
	p.stateMu.RLock()
	cmd, done := p.cmd, p.done
	p.stateMu.RUnlock()
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	// In particular, TUN file descriptors must be released before a new core
	// attempts to claim the same interface name.
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("等待 Xray 退出超时")
	}
}

func (p *process) GetTraffic(reset bool) ([]*Traffic, error) {
	if p.apiPort == 0 {
		return nil, common.NewError("xray api port wrong:", p.apiPort)
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%v", p.apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := statsservice.NewStatsServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	request := &statsservice.QueryStatsRequest{
		Reset_: reset,
	}
	resp, err := client.QueryStats(ctx, request)
	if err != nil {
		return nil, err
	}
	tagTrafficMap := map[string]*Traffic{}
	traffics := make([]*Traffic, 0)
	for _, stat := range resp.GetStat() {
		matchs := trafficRegex.FindStringSubmatch(stat.Name)
		if len(matchs) != 4 {
			continue
		}
		isInbound := matchs[1] == "inbound"
		tag := matchs[2]
		isDown := matchs[3] == "downlink"
		if tag == "api" {
			continue
		}
		traffic, ok := tagTrafficMap[tag]
		if !ok {
			traffic = &Traffic{
				IsInbound: isInbound,
				Tag:       tag,
			}
			tagTrafficMap[tag] = traffic
			traffics = append(traffics, traffic)
		}
		if isDown {
			traffic.Down = stat.Value
		} else {
			traffic.Up = stat.Value
		}
	}

	return traffics, nil
}

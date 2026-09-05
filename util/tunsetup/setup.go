// Package tunsetup manages an explicit, administrator-only systemd permission
// opt-in. Ordinary installations and online updates retain their existing sandbox.
package tunsetup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const dropIn = `# Managed by bx-ui tun enable. Remove using bx-ui tun disable.
[Service]
PrivateDevices=false
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
`

const dropInName = "50-bx-ui-tun.conf"

func Configure(enable bool) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("TUN 系统授权只能由 Linux root 管理员执行")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("TUN 系统授权需要 systemd 环境")
	}
	if enable {
		info, err := os.Stat("/dev/net/tun")
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return errors.New("系统没有可用的 /dev/net/tun，请先让服务器提供商启用 TUN 或由管理员加载 tun 模块")
		}
	}
	return configureAt("/etc/systemd/system/x-ui.service.d", enable, func(action string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		args := []string{action}
		if action == "restart" {
			args = append(args, "x-ui.service")
		}
		// #nosec G204 -- the command and arguments are fixed administrator operations.
		cmd := exec.CommandContext(ctx, "systemctl", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("systemctl %s 失败：%w；请检查服务状态后重试", action, err)
		}
		return nil
	})
}

func configureAt(dir string, enable bool, run func(string) error) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("TUN 服务配置目录无效或为符号链接")
	}
	target := filepath.Join(dir, dropInName)
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("TUN 服务配置不是普通文件，拒绝覆盖")
		}
		data, err := os.ReadFile(target) // #nosec G304 -- fixed managed file in a root-owned systemd directory.
		if err != nil {
			return err
		}
		if string(data) != dropIn {
			return errors.New("TUN 服务配置已被手动修改，请先备份并移走该文件")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if enable {
		file, err := os.CreateTemp(dir, ".bx-ui-tun-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		defer file.Close()
		if _, err := file.WriteString(dropIn); err != nil {
			return err
		}
		if err := file.Chmod(0644); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(file.Name(), target); err != nil {
			return err
		}
	} else if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := run("daemon-reload"); err != nil {
		return err
	}
	return run("restart")
}

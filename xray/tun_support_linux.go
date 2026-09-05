//go:build linux

package xray

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// CheckTUNSupport checks access without creating, attaching to, or changing an
// interface. In particular, never run a real TUN configuration as a preflight.
func CheckTUNSupport() error {
	const hint = "；请先由管理员执行 /usr/local/x-ui/x-ui tun enable（会重启面板），再重试"
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("TUN 设备不可访问：%w%s", err, hint)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("检查 TUN 设备失败：%w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(stat.Rdev)) != 10 || unix.Minor(uint64(stat.Rdev)) != 200 {
		return errors.New("/dev/net/tun 不是有效的 Linux TUN 设备")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		return fmt.Errorf("检查 TUN 权限失败：%w", err)
	}
	if capabilities[0].Effective&(1<<unix.CAP_NET_ADMIN) == 0 {
		return errors.New("TUN 缺少 CAP_NET_ADMIN 权限" + hint)
	}
	if os.Geteuid() != 0 {
		ambient, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, unix.CAP_NET_ADMIN, 0, 0)
		if err != nil || ambient != 1 {
			return errors.New("Xray 子进程无法继承 TUN 权限" + hint)
		}
	}
	return nil
}

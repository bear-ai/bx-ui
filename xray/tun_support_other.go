//go:build !linux

package xray

import "errors"

func CheckTUNSupport() error {
	return errors.New("面板的 TUN 入站目前仅支持 Linux 部署")
}

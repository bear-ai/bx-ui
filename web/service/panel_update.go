package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"x-ui/config"
	"x-ui/logger"
)

const (
	maxPanelArchiveSize = int64(100 << 20)
	maxPanelBinarySize  = int64(100 << 20)
)

var (
	panelVersionPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	panelChecksumPattern     = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	panelReleaseAPIURL       = "https://api.github.com/repos/bear-ai/bx-ui/releases/latest"
	panelReleaseDownloadBase = "https://github.com/bear-ai/bx-ui/releases/download"
	panelRestartDelay        = 1500 * time.Millisecond
	signalPanelRestart       = func() error { return syscall.Kill(os.Getpid(), syscall.SIGTERM) }
)

type PanelUpdateInfo struct {
	CurrentVersion  string `json:"currentVersion"`
	LatestVersion   string `json:"latestVersion"`
	UpdateAvailable bool   `json:"updateAvailable"`
	ReleaseURL      string `json:"releaseUrl"`
}

type panelRelease struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

func parsePanelVersion(value string) ([3]uint64, error) {
	var result [3]uint64
	if !panelVersionPattern.MatchString(value) {
		return result, errors.New("面板版本号格式无效")
	}
	for index, part := range strings.Split(value, ".") {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return result, errors.New("面板版本号格式无效")
		}
		result[index] = number
	}
	return result, nil
}

func isPanelUpdateAvailable(current, latest string) (bool, error) {
	currentParts, err := parsePanelVersion(current)
	if err != nil {
		return false, err
	}
	latestParts, err := parsePanelVersion(latest)
	if err != nil {
		return false, err
	}
	for index := range currentParts {
		if latestParts[index] > currentParts[index] {
			return true, nil
		}
		if latestParts[index] < currentParts[index] {
			return false, nil
		}
	}
	return false, nil
}

func (s *ServerService) GetPanelUpdate() (*PanelUpdateInfo, error) {
	data, err := getLimited(panelReleaseAPIURL, 512<<10)
	if err != nil {
		return nil, err
	}
	release := &panelRelease{}
	if err := json.Unmarshal(data, release); err != nil {
		return nil, err
	}
	if release.Draft || release.Prerelease {
		return nil, errors.New("最新发布不是正式版本")
	}
	available, err := isPanelUpdateAvailable(config.GetVersion(), release.TagName)
	if err != nil {
		return nil, err
	}
	return &PanelUpdateInfo{
		CurrentVersion:  config.GetVersion(),
		LatestVersion:   release.TagName,
		UpdateAvailable: available,
		ReleaseURL:      release.HTMLURL,
	}, nil
}

func panelArchiveName() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("在线更新仅支持 Linux 系统")
	}
	switch runtime.GOARCH {
	case "amd64", "arm64", "s390x":
		return fmt.Sprintf("x-ui-linux-%s.tar.gz", runtime.GOARCH), nil
	default:
		return "", fmt.Errorf("在线更新暂不支持 %s 架构", runtime.GOARCH)
	}
}

func downloadPanelFile(url, pattern string, limit int64) (string, error) {
	resp, err := releaseHTTPClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败: HTTP %s", resp.Status)
	}
	if resp.ContentLength > limit {
		return "", errors.New("面板安装包超过大小限制")
	}
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	written, err := io.Copy(file, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", errors.New("面板安装包超过大小限制")
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func expectedPanelChecksum(data []byte) (string, error) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 || !panelChecksumPattern.MatchString(fields[0]) {
		return "", errors.New("面板安装包校验文件无效")
	}
	return strings.ToLower(fields[0]), nil
}

func verifyPanelChecksum(fileName string, checksumData []byte) error {
	wanted, err := expectedPanelChecksum(checksumData)
	if err != nil {
		return err
	}
	file, err := os.Open(fileName) // #nosec G304 -- this path is created by os.CreateTemp above.
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != wanted {
		return errors.New("面板安装包 SHA-256 校验失败")
	}
	return nil
}

func extractPanelExecutable(archiveName, targetDir string) (string, error) {
	archive, err := os.Open(archiveName) // #nosec G304 -- this path is created by os.CreateTemp above.
	if err != nil {
		return "", err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return "", errors.New("安装包中缺少面板程序")
		}
		if err != nil {
			return "", err
		}
		if pathpkg.Clean(header.Name) != "x-ui/x-ui" {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return "", errors.New("安装包中的面板程序类型无效")
		}
		if header.Size <= 0 || header.Size > maxPanelBinarySize {
			return "", errors.New("安装包中的面板程序大小无效")
		}
		file, err := os.CreateTemp(targetDir, ".bx-ui-panel-*")
		if err != nil {
			return "", err
		}
		name := file.Name()
		ok := false
		defer func() {
			_ = file.Close()
			if !ok {
				_ = os.Remove(name)
			}
		}()
		written, err := io.Copy(file, io.LimitReader(tarReader, maxPanelBinarySize+1))
		if err != nil {
			return "", err
		}
		if written != header.Size || written > maxPanelBinarySize {
			return "", errors.New("安装包中的面板程序内容无效")
		}
		if err := file.Chmod(0755); err != nil {
			return "", err
		}
		if err := file.Sync(); err != nil {
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		ok = true
		return name, nil
	}
}

func panelExecutableVersion(fileName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- the executable came from a checksum-verified project release.
	output, err := exec.CommandContext(ctx, fileName, "-v").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("校验新版面板失败: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func copyPanelExecutable(source, target string) error {
	input, err := os.Open(source) // #nosec G304 -- source is the running executable.
	if err != nil {
		return err
	}
	defer input.Close()
	file, err := os.CreateTemp(filepath.Dir(target), ".bx-ui-backup-*")
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	written, err := io.Copy(file, io.LimitReader(input, maxPanelBinarySize+1))
	if err != nil {
		return err
	}
	if written > maxPanelBinarySize {
		return errors.New("当前面板程序超过大小限制")
	}
	if err := file.Chmod(0755); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, target); err != nil {
		return err
	}
	ok = true
	return nil
}

func writePanelUpdateMarker(fileName string) error {
	file, err := os.CreateTemp(filepath.Dir(fileName), ".bx-ui-marker-*")
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := file.WriteString("pending\n"); err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, fileName); err != nil {
		return err
	}
	ok = true
	return nil
}

func (s *ServerService) UpdatePanel() (*PanelUpdateInfo, error) {
	if os.Getenv("INVOCATION_ID") == "" {
		return nil, errors.New("在线更新仅支持 systemd 安装的面板")
	}
	info, err := s.GetPanelUpdate()
	if err != nil {
		return nil, err
	}
	if !info.UpdateAvailable {
		return info, errors.New("当前已经是最新版本")
	}
	archiveFile, err := panelArchiveName()
	if err != nil {
		return nil, err
	}
	baseURL := fmt.Sprintf("%s/%s", panelReleaseDownloadBase, info.LatestVersion)
	archiveURL := fmt.Sprintf("%s/%s", baseURL, archiveFile)
	downloaded, err := downloadPanelFile(archiveURL, "bx-ui-panel-*.tar.gz", maxPanelArchiveSize)
	if err != nil {
		return nil, err
	}
	defer os.Remove(downloaded)
	checksumData, err := getLimited(archiveURL+".sha256", 4096)
	if err != nil {
		return nil, err
	}
	if err := verifyPanelChecksum(downloaded, checksumData); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	if filepath.Base(executable) != "x-ui" {
		return nil, errors.New("无法确认当前面板程序路径")
	}
	stat, err := os.Lstat(executable)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, errors.New("当前面板程序不是普通文件")
	}
	candidate, err := extractPanelExecutable(downloaded, filepath.Dir(executable))
	if err != nil {
		return nil, err
	}
	defer os.Remove(candidate)
	candidateVersion, err := panelExecutableVersion(candidate)
	if err != nil {
		return nil, err
	}
	if candidateVersion != info.LatestVersion {
		return nil, fmt.Errorf("安装包版本不匹配: 期望 %s，实际 %s", info.LatestVersion, candidateVersion)
	}
	previous := executable + ".previous"
	marker := executable + ".update-pending"
	if _, err := os.Stat(marker); err == nil {
		return nil, errors.New("上一次面板更新尚未完成，请先检查服务状态")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := copyPanelExecutable(executable, previous); err != nil {
		return nil, fmt.Errorf("备份当前面板失败: %w", err)
	}
	if err := writePanelUpdateMarker(marker); err != nil {
		return nil, fmt.Errorf("写入更新状态失败: %w", err)
	}
	if err := os.Rename(candidate, executable); err != nil {
		_ = os.Remove(marker)
		return nil, fmt.Errorf("替换面板程序失败: %w", err)
	}
	return info, nil
}

func (s *ServerService) SchedulePanelRestart() {
	go func() {
		time.Sleep(panelRestartDelay)
		if err := signalPanelRestart(); err != nil {
			logger.Error("restart panel after update failed:", err)
		}
	}()
}

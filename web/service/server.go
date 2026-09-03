package service

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"x-ui/logger"
	"x-ui/util/sys"
	"x-ui/xray"
)

type ProcessState string

const (
	Running ProcessState = "running"
	Stop    ProcessState = "stop"
	Error   ProcessState = "error"
)

type Status struct {
	T   time.Time `json:"-"`
	Cpu float64   `json:"cpu"`
	Mem struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"mem"`
	Swap struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"swap"`
	Disk struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"disk"`
	Xray struct {
		State    ProcessState `json:"state"`
		ErrorMsg string       `json:"errorMsg"`
		Version  string       `json:"version"`
	} `json:"xray"`
	Uptime   uint64    `json:"uptime"`
	Loads    []float64 `json:"loads"`
	TcpCount int       `json:"tcpCount"`
	UdpCount int       `json:"udpCount"`
	NetIO    struct {
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	} `json:"netIO"`
	NetTraffic struct {
		Sent uint64 `json:"sent"`
		Recv uint64 `json:"recv"`
	} `json:"netTraffic"`
}

type Release struct {
	TagName string `json:"tag_name"`
}

type ServerService struct {
	xrayService XrayService
}

var (
	releaseVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	releaseHTTPClient     = &http.Client{Timeout: 2 * time.Minute}
)

func getLimited(url string, limit int64) ([]byte, error) {
	resp, err := releaseHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("download exceeded size limit")
	}
	return data, nil
}

func (s *ServerService) GetStatus(lastStatus *Status) *Status {
	now := time.Now()
	status := &Status{
		T: now,
	}

	percents, err := cpu.Percent(0, false)
	if err != nil {
		logger.Warning("get cpu percent failed:", err)
	} else {
		status.Cpu = percents[0]
	}

	upTime, err := host.Uptime()
	if err != nil {
		logger.Warning("get uptime failed:", err)
	} else {
		status.Uptime = upTime
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		logger.Warning("get virtual memory failed:", err)
	} else {
		status.Mem.Current = memInfo.Used
		status.Mem.Total = memInfo.Total
	}

	swapInfo, err := mem.SwapMemory()
	if err != nil {
		logger.Warning("get swap memory failed:", err)
	} else {
		status.Swap.Current = swapInfo.Used
		status.Swap.Total = swapInfo.Total
	}

	distInfo, err := disk.Usage("/")
	if err != nil {
		logger.Warning("get dist usage failed:", err)
	} else {
		status.Disk.Current = distInfo.Used
		status.Disk.Total = distInfo.Total
	}

	avgState, err := load.Avg()
	if err != nil {
		logger.Warning("get load avg failed:", err)
	} else {
		status.Loads = []float64{avgState.Load1, avgState.Load5, avgState.Load15}
	}

	ioStats, err := net.IOCounters(false)
	if err != nil {
		logger.Warning("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		ioStat := ioStats[0]
		status.NetTraffic.Sent = ioStat.BytesSent
		status.NetTraffic.Recv = ioStat.BytesRecv

		if lastStatus != nil {
			duration := now.Sub(lastStatus.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(status.NetTraffic.Sent-lastStatus.NetTraffic.Sent) / seconds)
			down := uint64(float64(status.NetTraffic.Recv-lastStatus.NetTraffic.Recv) / seconds)
			status.NetIO.Up = up
			status.NetIO.Down = down
		}
	} else {
		logger.Warning("can not find io counters")
	}

	status.TcpCount, err = sys.GetTCPCount()
	if err != nil {
		logger.Warning("get tcp connections failed:", err)
	}

	status.UdpCount, err = sys.GetUDPCount()
	if err != nil {
		logger.Warning("get udp connections failed:", err)
	}

	if s.xrayService.IsXrayRunning() {
		status.Xray.State = Running
		status.Xray.ErrorMsg = ""
	} else {
		err := s.xrayService.GetXrayErr()
		if err != nil {
			status.Xray.State = Error
		} else {
			status.Xray.State = Stop
		}
		status.Xray.ErrorMsg = s.xrayService.GetXrayResult()
	}
	status.Xray.Version = s.xrayService.GetXrayVersion()

	return status
}

func (s *ServerService) GetXrayVersions() ([]string, error) {
	url := "https://api.github.com/repos/XTLS/Xray-core/releases"
	data, err := getLimited(url, 2<<20)
	if err != nil {
		return nil, err
	}

	releases := make([]Release, 0)
	err = json.Unmarshal(data, &releases)
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(releases))
	for _, release := range releases {
		versions = append(versions, release.TagName)
	}
	return versions, nil
}

func (s *ServerService) downloadXRay(version string) (string, error) {
	if !releaseVersionPattern.MatchString(version) {
		return "", errors.New("invalid Xray release version")
	}
	osName := runtime.GOOS
	arch := runtime.GOARCH

	switch osName {
	case "darwin":
		osName = "macos"
	}

	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	}

	fileName := fmt.Sprintf("Xray-%s-%s.zip", osName, arch)
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, fileName)
	resp, err := releaseHTTPClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %s", resp.Status)
	}

	file, err := os.CreateTemp("", "bx-ui-xray-*.zip")
	if err != nil {
		return "", err
	}
	tempName := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(tempName)
		}
	}()

	written, err := io.Copy(file, io.LimitReader(resp.Body, (200<<20)+1))
	if err != nil {
		return "", err
	}
	if written > 200<<20 {
		return "", errors.New("Xray archive exceeded size limit")
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	digestData, err := getLimited(url+".dgst", 4096)
	if err != nil {
		return "", err
	}
	wanted := ""
	scanner := bufio.NewScanner(strings.NewReader(string(digestData)))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "SHA2-256=") {
			wanted = strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "SHA2-256="))
			break
		}
	}
	if wanted == "" || !strings.EqualFold(wanted, fmt.Sprintf("%x", hash.Sum(nil))) {
		return "", errors.New("Xray archive SHA-256 verification failed")
	}
	if err = file.Close(); err != nil {
		return "", err
	}

	keep = true
	return tempName, nil
}

func (s *ServerService) UpdateXray(version string) error {
	zipFileName, err := s.downloadXRay(version)
	if err != nil {
		return err
	}

	zipFile, err := os.Open(zipFileName) // #nosec G304 -- path comes only from os.CreateTemp above.
	if err != nil {
		return err
	}
	defer func() {
		_ = zipFile.Close()
		_ = os.Remove(zipFileName)
	}()

	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return err
	}

	type extractedFile struct {
		temp   string
		target string
	}
	extracted := make([]extractedFile, 0, 3)
	defer func() {
		for _, file := range extracted {
			_ = os.Remove(file.temp)
		}
	}()

	extractZipFile := func(zipName, target string, mode os.FileMode) error {
		archiveFile, err := reader.Open(zipName)
		if err != nil {
			return err
		}
		defer archiveFile.Close()
		file, err := os.CreateTemp(filepath.Dir(target), ".bx-ui-update-*")
		if err != nil {
			return err
		}
		tempName := file.Name()
		ok := false
		defer func() {
			_ = file.Close()
			if !ok {
				_ = os.Remove(tempName)
			}
		}()
		written, err := io.Copy(file, io.LimitReader(archiveFile, (300<<20)+1))
		if err != nil || written > 300<<20 {
			if err == nil {
				err = errors.New("archive member exceeded size limit")
			}
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Chmod(mode); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		extracted = append(extracted, extractedFile{temp: tempName, target: target})
		ok = true
		return nil
	}

	err = extractZipFile("xray", xray.GetBinaryPath(), 0755)
	if err != nil {
		return err
	}
	err = extractZipFile("geosite.dat", xray.GetGeositePath(), 0644)
	if err != nil {
		return err
	}
	err = extractZipFile("geoip.dat", xray.GetGeoipPath(), 0644)
	if err != nil {
		return err
	}

	if err := s.xrayService.StopXray(); err != nil && err.Error() != "xray is not running" {
		return err
	}
	defer func() {
		if restartErr := s.xrayService.RestartXray(true); restartErr != nil {
			logger.Error("start xray failed:", restartErr)
		}
	}()
	for _, file := range extracted {
		if err := os.Rename(file.temp, file.target); err != nil {
			return err
		}
	}

	return nil

}

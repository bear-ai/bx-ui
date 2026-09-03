package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"x-ui/logger"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/idna"
)

const (
	managedCertificateDir  = "/etc/x-ui/certs"
	certificateRenewBefore = 15 * 24 * time.Hour
	acmeRequestTimeout     = 110 * time.Second
	challengePrefix        = "/.well-known/acme-challenge/"
)

type CertificateStatus struct {
	Domain             string   `json:"domain"`
	HTTPSPort          int      `json:"httpsPort"`
	State              string   `json:"state"`
	Message            string   `json:"message"`
	Issuer             string   `json:"issuer"`
	ExpiresAt          string   `json:"expiresAt"`
	DaysRemaining      int      `json:"daysRemaining"`
	RenewalDue         bool     `json:"renewalDue"`
	CertificatePresent bool     `json:"certificatePresent"`
	HTTPSURL           string   `json:"httpsUrl"`
	DNSAddresses       []string `json:"dnsAddresses,omitempty"`
	DNSReady           bool     `json:"dnsReady"`
	HTTPReady          bool     `json:"httpReady"`
}

type CertificateApplyResult struct {
	Status          *CertificateStatus `json:"status"`
	Issued          bool               `json:"issued"`
	RestartRequired bool               `json:"restartRequired"`
}

type certificateMaterial struct {
	certificatePEM []byte
	privateKeyPEM  []byte
}

type CertificateService struct {
	mu                sync.RWMutex
	issueMu           sync.Mutex
	tokens            map[string]string
	challengeServer   *http.Server
	challengeListener net.Listener
	currentHTTPPort   int
	currentHTTPSPort  int

	storageDir   string
	directoryURL string
	now          func() time.Time
	lookupIP     func(context.Context, string, string) ([]net.IP, error)
	issueFunc    func(context.Context, string) (*certificateMaterial, error)
}

func NewCertificateService() *CertificateService {
	return &CertificateService{
		tokens:       make(map[string]string),
		storageDir:   managedCertificateDir,
		directoryURL: acme.LetsEncryptURL,
		now:          time.Now,
		lookupIP:     net.DefaultResolver.LookupIP,
	}
}

func normalizeCertificateDomain(value string) (string, error) {
	domain := strings.TrimSuffix(strings.TrimSpace(value), ".")
	if domain == "" {
		return "", errors.New("请先填写并保存面板域名")
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("域名格式无效: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 || !strings.Contains(ascii, ".") || net.ParseIP(ascii) != nil || strings.Contains(ascii, "*") {
		return "", errors.New("域名必须是有效的公网完整域名，不能填写 IP 或通配符")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("域名标签格式无效")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("域名包含不支持的字符")
			}
		}
	}
	return ascii, nil
}

func isPublicAddress(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func (s *CertificateService) lookupPublicAddresses(ctx context.Context, domain string) ([]string, error) {
	ips, err := s.lookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, fmt.Errorf("域名解析失败: %w", err)
	}
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if !isPublicAddress(ip) {
			return nil, fmt.Errorf("域名解析到了非公网地址 %s，请检查 DNS 记录", ip.String())
		}
		seen[ip.String()] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, errors.New("域名没有可用的 A 或 AAAA 记录")
	}
	addresses := make([]string, 0, len(seen))
	for address := range seen {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses, nil
}

func (s *CertificateService) setChallenge(path, response string) func() {
	s.mu.Lock()
	s.tokens[path] = response
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.tokens, path)
		s.mu.Unlock()
	}
}

func (s *CertificateService) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePrefix) {
			s.mu.RLock()
			response, ok := s.tokens[r.URL.Path]
			s.mu.RUnlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, response)
			return
		}
		if fallback == nil {
			http.NotFound(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

func (s *CertificateService) EnsureChallengeServer(webPort int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentHTTPPort != 0 {
		webPort = s.currentHTTPPort
	}
	if webPort == 80 {
		return nil
	}
	if s.challengeListener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", ":80") // #nosec G102 -- HTTP-01 must be reachable on every public interface.
	if err != nil {
		return fmt.Errorf("无法监听公网 80 端口，请检查端口占用和防火墙: %w", err)
	}
	server := &http.Server{
		Handler:           s.HTTPChallengeHandler(nil),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	s.challengeListener = listener
	s.challengeServer = server
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Errorf("ACME HTTP-01 server failed: %v", serveErr)
		}
	}()
	logger.Info("ACME HTTP-01 challenge server run on", listener.Addr())
	return nil
}

func (s *CertificateService) SetCurrentHTTPPort(port int) {
	s.mu.Lock()
	s.currentHTTPPort = port
	s.mu.Unlock()
}

func (s *CertificateService) SetCurrentHTTPSPort(port int) {
	s.mu.Lock()
	s.currentHTTPSPort = port
	s.mu.Unlock()
}

func (s *CertificateService) checkHTTPSPortAvailable(listen string, port int) error {
	s.mu.RLock()
	currentHTTPSPort := s.currentHTTPSPort
	s.mu.RUnlock()
	if currentHTTPSPort == port {
		return nil
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(listen, fmt.Sprint(port)))
	if err != nil {
		return fmt.Errorf("HTTPS 端口 %d 无法监听，请检查端口占用: %w", port, err)
	}
	return listener.Close()
}

func (s *CertificateService) StopChallengeServer(ctx context.Context) error {
	s.mu.Lock()
	server := s.challengeServer
	listener := s.challengeListener
	s.challengeServer = nil
	s.challengeListener = nil
	s.mu.Unlock()
	if server == nil {
		return nil
	}
	err := server.Shutdown(ctx)
	if listener != nil {
		closeErr := listener.Close()
		if err == nil && !errors.Is(closeErr, net.ErrClosed) {
			err = closeErr
		}
	}
	return err
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (s *CertificateService) checkHTTPReachability(ctx context.Context, domain string, addresses []string) error {
	token, err := randomHex(18)
	if err != nil {
		return err
	}
	path := challengePrefix + "bx-ui-probe-" + token
	response := "bx-ui-http01-" + token
	cleanup := s.setChallenge(path, response)
	defer cleanup()

	for _, address := range addresses {
		address := address
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(dialCtx context.Context, network, target string) (net.Conn, error) {
			_, port, splitErr := net.SplitHostPort(target)
			if splitErr != nil {
				return nil, splitErr
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, network, net.JoinHostPort(address, port))
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects while checking HTTP-01")
				}
				if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
					return errors.New("HTTP-01 check redirected to another domain")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return errors.New("HTTP-01 check used an unsupported redirect scheme")
				}
				return nil
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("无法通过解析地址 %s 的公网 80 端口访问本机: %w", address, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("读取 HTTP-01 检测响应失败: %w", readErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if resp.StatusCode != http.StatusOK || len(body) > 4096 || string(body) != response {
			return fmt.Errorf("解析地址 %s 的公网 80 端口未返回本面板验证内容（HTTP %d），请检查 DNS、防火墙、NAT 或反向代理", address, resp.StatusCode)
		}
	}
	return nil
}

func managedHTTPSURL(domain string, port int) string {
	host := domain
	if port != 443 {
		host = net.JoinHostPort(domain, fmt.Sprint(port))
	}
	return "https://" + host
}

func (s *CertificateService) CheckDomain(ctx context.Context) (*CertificateStatus, error) {
	settings := &SettingService{}
	domainValue, err := settings.GetDomain()
	if err != nil {
		return nil, err
	}
	domain, err := normalizeCertificateDomain(domainValue)
	if err != nil {
		return nil, err
	}
	webPort, err := settings.GetPort()
	if err != nil {
		return nil, err
	}
	httpsPort, err := settings.GetHTTPSPort()
	if err != nil {
		return nil, err
	}
	addresses, err := s.lookupPublicAddresses(ctx, domain)
	if err != nil {
		return nil, err
	}
	if err := s.EnsureChallengeServer(webPort); err != nil {
		return nil, err
	}
	listen, err := settings.GetListen()
	if err != nil {
		return nil, err
	}
	if err := s.checkHTTPSPortAvailable(listen, httpsPort); err != nil {
		return nil, err
	}
	if err := s.checkHTTPReachability(ctx, domain, addresses); err != nil {
		return nil, err
	}
	status, _ := s.statusFor(domain, httpsPort)
	status.DNSAddresses = addresses
	status.DNSReady = true
	status.HTTPReady = true
	if status.CertificatePresent {
		status.Message += "；域名解析和公网 80 端口检测通过"
	} else {
		status.Message = "域名解析和公网 80 端口检测通过，可以申请证书"
	}
	return status, nil
}

func (s *CertificateService) certificatePaths() (string, string) {
	current := filepath.Join(s.storageDir, "current")
	return filepath.Join(current, "fullchain.pem"), filepath.Join(current, "privkey.pem")
}

func (s *CertificateService) loadCertificate(domain string) (*tls.Certificate, *x509.Certificate, error) {
	root, err := os.OpenRoot(s.storageDir)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	currentTarget, err := root.Readlink("current")
	if err != nil {
		return nil, nil, err
	}
	certificatePEM, err := root.ReadFile(filepath.Join(currentTarget, "fullchain.pem"))
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM, err := root.ReadFile(filepath.Join(currentTarget, "privkey.pem"))
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, nil, fmt.Errorf("certificate does not match %s: %w", domain, err)
	}
	cert.Leaf = leaf
	return &cert, leaf, nil
}

func (s *CertificateService) statusFor(domain string, httpsPort int) (*CertificateStatus, error) {
	status := &CertificateStatus{
		Domain:     domain,
		HTTPSPort:  httpsPort,
		State:      "pending",
		Message:    "尚未申请证书",
		HTTPSURL:   managedHTTPSURL(domain, httpsPort),
		ExpiresAt:  "",
		RenewalDue: false,
		HTTPReady:  false,
		DNSReady:   false,
	}
	_, leaf, err := s.loadCertificate(domain)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return status, nil
		}
		status.State = "invalid"
		status.Message = "已保存的证书无效: " + err.Error()
		return status, err
	}
	status.CertificatePresent = true
	status.Issuer = leaf.Issuer.CommonName
	status.ExpiresAt = leaf.NotAfter.UTC().Format(time.RFC3339)
	remaining := leaf.NotAfter.Sub(s.now())
	status.DaysRemaining = int(remaining.Hours() / 24)
	status.RenewalDue = remaining <= certificateRenewBefore
	switch {
	case remaining <= 0:
		status.State = "expired"
		status.Message = "证书已过期，将保留 HTTP 面板访问"
	case status.RenewalDue:
		status.State = "expiring"
		status.Message = "证书将在 15 天内到期，系统会自动续期"
	default:
		status.State = "valid"
		status.Message = "证书有效，系统将在到期前 15 天自动续期"
	}
	return status, nil
}

func (s *CertificateService) GetStatus() (*CertificateStatus, error) {
	settings := &SettingService{}
	domainValue, err := settings.GetDomain()
	if err != nil {
		return nil, err
	}
	httpsPort, err := settings.GetHTTPSPort()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(domainValue) == "" {
		return &CertificateStatus{State: "unconfigured", HTTPSPort: httpsPort, Message: "请先绑定面板域名"}, nil
	}
	domain, err := normalizeCertificateDomain(domainValue)
	if err != nil {
		return nil, err
	}
	status, statusErr := s.statusFor(domain, httpsPort)
	if status != nil {
		return status, nil
	}
	return nil, statusErr
}

func (s *CertificateService) ManagedCertificate() (*tls.Certificate, *x509.Certificate, error) {
	settings := &SettingService{}
	domainValue, err := settings.GetDomain()
	if err != nil {
		return nil, nil, err
	}
	domain, err := normalizeCertificateDomain(domainValue)
	if err != nil {
		return nil, nil, err
	}
	cert, leaf, err := s.loadCertificate(domain)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, nil, errors.New("managed certificate is not currently valid")
	}
	return cert, leaf, nil
}

func writePrivateFile(root *os.Root, path string, data []byte) error {
	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
			_ = root.Remove(path)
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	ok = err == nil
	return err
}

func (s *CertificateService) activateCertificate(domain string, material *certificateMaterial) error {
	cert, err := tls.X509KeyPair(material.certificatePEM, material.privateKeyPEM)
	if err != nil {
		return fmt.Errorf("签发结果中的证书和私钥不匹配: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("签发结果中没有证书")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return fmt.Errorf("签发证书与域名不匹配: %w", err)
	}
	now := s.now()
	if now.Before(leaf.NotBefore.Add(-5*time.Minute)) || !now.Before(leaf.NotAfter) {
		return errors.New("签发证书当前不在有效期内")
	}
	if err := os.MkdirAll(filepath.Join(s.storageDir, "versions"), 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.storageDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Chmod(".", 0700); err != nil { // #nosec G302 -- directories require owner execute permission.
		return err
	}
	suffix, err := randomHex(6)
	if err != nil {
		return err
	}
	versionName := fmt.Sprintf("%d-%s", now.UTC().Unix(), suffix)
	versionDir := filepath.Join("versions", versionName)
	if err := root.Mkdir(versionDir, 0700); err != nil {
		return err
	}
	if err := writePrivateFile(root, filepath.Join(versionDir, "fullchain.pem"), material.certificatePEM); err != nil {
		return err
	}
	if err := writePrivateFile(root, filepath.Join(versionDir, "privkey.pem"), material.privateKeyPEM); err != nil {
		return err
	}
	linkName := ".current-" + suffix
	if err := root.Symlink(filepath.Join("versions", versionName), linkName); err != nil {
		return err
	}
	if err := root.Rename(linkName, "current"); err != nil {
		_ = root.Remove(linkName)
		return err
	}
	return nil
}

func (s *CertificateService) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(s.storageDir, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.storageDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := root.ReadFile("account.key")
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("ACME 账户私钥格式无效")
		}
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("解析 ACME 账户私钥失败: %w", parseErr)
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ACME 账户私钥类型无效")
		}
		return ecdsaKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writePrivateFile(root, "account.key", encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			return s.loadOrCreateAccountKey()
		}
		return nil, err
	}
	return key, nil
}

func (s *CertificateService) requestCertificate(ctx context.Context, domain string) (*certificateMaterial, error) {
	accountKey, err := s.loadOrCreateAccountKey()
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: s.directoryURL, UserAgent: "bx-ui-acme"}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("注册 ACME 账户失败: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("创建证书订单失败: %w", err)
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return nil, fmt.Errorf("读取域名授权失败: %w", err)
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		if authorization.Status != acme.StatusPending {
			return nil, fmt.Errorf("域名授权状态无效: %s", authorization.Status)
		}
		var challenge *acme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate.Type == "http-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return nil, errors.New("证书机构未提供 HTTP-01 验证方式")
		}
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return nil, err
		}
		cleanup := s.setChallenge(client.HTTP01ChallengePath(challenge.Token), response)
		if _, err = client.Accept(ctx, challenge); err == nil {
			_, err = client.WaitAuthorization(ctx, authorizationURL)
		}
		cleanup()
		if err != nil {
			return nil, fmt.Errorf("HTTP-01 域名验证失败: %w", err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("等待证书订单失败: %w", err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certificateKey)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}
	var certificatePEM []byte
	for _, der := range chain {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificateKey)
	if err != nil {
		return nil, err
	}
	return &certificateMaterial{
		certificatePEM: certificatePEM,
		privateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func (s *CertificateService) issueAndActivate(ctx context.Context, domain string) error {
	issue := s.issueFunc
	if issue == nil {
		issue = s.requestCertificate
	}
	material, err := issue(ctx, domain)
	if err != nil {
		return err
	}
	return s.activateCertificate(domain, material)
}

func (s *CertificateService) ApplyCertificate(ctx context.Context) (*CertificateApplyResult, error) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	checked, err := s.CheckDomain(ctx)
	if err != nil {
		return nil, err
	}
	if checked.CertificatePresent && checked.State == "valid" {
		return &CertificateApplyResult{Status: checked}, nil
	}
	domain := checked.Domain
	requestCtx, cancel := context.WithTimeout(ctx, acmeRequestTimeout)
	defer cancel()
	if err := s.issueAndActivate(requestCtx, domain); err != nil {
		logger.Errorf("issue managed certificate for %s failed: %v", domain, err)
		return nil, err
	}
	status, err := s.statusFor(domain, checked.HTTPSPort)
	if err != nil {
		return nil, err
	}
	status.DNSAddresses = checked.DNSAddresses
	status.DNSReady = true
	status.HTTPReady = true
	return &CertificateApplyResult{Status: status, Issued: true, RestartRequired: true}, nil
}

func (s *CertificateService) RenewIfNeeded(ctx context.Context) (bool, error) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	settings := &SettingService{}
	domainValue, err := settings.GetDomain()
	if err != nil || strings.TrimSpace(domainValue) == "" {
		return false, err
	}
	domain, err := normalizeCertificateDomain(domainValue)
	if err != nil {
		return false, err
	}
	httpsPort, err := settings.GetHTTPSPort()
	if err != nil {
		return false, err
	}
	status, statusErr := s.statusFor(domain, httpsPort)
	if !status.CertificatePresent {
		return false, statusErr
	}
	if !status.RenewalDue {
		return false, statusErr
	}
	webPort, err := settings.GetPort()
	if err != nil {
		return false, err
	}
	if _, err := s.lookupPublicAddresses(ctx, domain); err != nil {
		return false, err
	}
	if err := s.EnsureChallengeServer(webPort); err != nil {
		return false, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, acmeRequestTimeout)
	defer cancel()
	if err := s.issueAndActivate(requestCtx, domain); err != nil {
		return false, err
	}
	logger.Infof("managed certificate for %s renewed successfully", domain)
	return true, nil
}

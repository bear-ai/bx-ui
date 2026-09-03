# x-ui

支持多协议多用户的 xray 面板

# 功能介绍

- 系统状态监控
- 显示面板版本，支持检查并在线更新面板
- 支持多用户多协议，网页可视化操作
- 支持 Xray 原生入站协议：vmess、vless、trojan、shadowsocks、dokodemo-door/tunnel、socks/mixed、http、wireguard、hysteria2、tun
- 支持 tcp/raw、mKCP、WebSocket、gRPC、HTTPUpgrade、XHTTP、Hysteria 传输，以及 TLS、REALITY、VLESS Encryption
- 支持 VMess 全部客户端加密和 Shadowsocks AEAD/2022-blake3 全部加密方式
- 流量统计，限制流量，限制到期时间
- 可自定义 xray 配置模板
- 支持绑定面板域名并设置独立 HTTPS 端口
- 支持 Let's Encrypt HTTP-01 一键申请证书，并在到期前 15 天自动续期
- 更多高级配置项，详见面板

> 新增协议、REALITY 和 VLESS Encryption 以 Xray v26.3.27 为兼容基线。MTProto、AmneziaWG 在 3x-ui 中由额外的 sidecar/自定义网络栈提供，并非 Xray 原生入站，因此本项目不提供不可运行的占位选项。

# 安装&升级

```
bash <(curl -Ls https://raw.githubusercontent.com/bear-ai/bx-ui/main/install.sh)
```

## 手动安装&升级

1. 首先从 https://github.com/bear-ai/bx-ui/releases 下载最新的压缩包，一般选择 `amd64`架构
2. 然后将这个压缩包上传到服务器的 `/root/`目录下，并使用 `root`用户登录服务器

> 如果你的服务器 cpu 架构不是 `amd64`，自行将命令中的 `amd64`替换为其他架构

```
cd /root/
rm x-ui/ /usr/local/x-ui/ /usr/bin/x-ui -rf
tar zxvf x-ui-linux-amd64.tar.gz
chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh x-ui/x-ui-update-guard
cp x-ui/x-ui.sh /usr/bin/x-ui
cp -f x-ui/x-ui.service /etc/systemd/system/
mv x-ui/ /usr/local/
systemctl daemon-reload
systemctl enable x-ui
systemctl restart x-ui
```

## SSL证书申请

面板设置页内置 Let's Encrypt 证书申请和续期功能：

1. 填写“绑定域名”和“面板 HTTPS 端口”，保存配置。
2. 将域名的 A/AAAA 记录解析到面板服务器。
3. 确保公网 TCP 80 端口可直接访问本服务器，点击“检测解析和 80 端口”。
4. 检测通过后点击“申请证书”。签发成功后面板会自动重启并启用 HTTPS。

证书与私钥存放于 `/etc/x-ui/certs`，仅面板服务账户可读写。证书到期前 15 天会自动续期；续期失败时保留原证书并每天重试，不会覆盖仍可使用的证书。

本功能仅支持 ACME HTTP-01，不支持 DNS-01 和泛域名证书。若 80 端口被 Nginx、Caddy 等程序占用，需要先释放该端口。

## Tg机器人使用（开发中，暂不可使用）

> 此功能与教程由[FranzKafkaYu](https://github.com/FranzKafkaYu)提供

X-UI支持通过Tg机器人实现每日流量通知，面板登录提醒等功能，使用Tg机器人，需要自行申请
具体申请教程可以参考[博客链接](https://coderfan.net/how-to-use-telegram-bot-to-alarm-you-when-someone-login-into-your-vps.html)
使用说明:在面板后台设置机器人相关参数，具体包括

- Tg机器人Token
- Tg机器人ChatId
- Tg机器人周期运行时间，采用crontab语法  

参考语法：
- 30 * * * * * //每一分的第30s进行通知
- @hourly      //每小时通知
- @daily       //每天通知（凌晨零点整）
- @every 8h    //每8小时通知  

TG通知内容：
- 节点流量使用
- 面板登录提醒
- 节点到期提醒
- 流量预警提醒  

更多功能规划中...
## 建议系统

- CentOS 7+
- Ubuntu 16+
- Debian 8+

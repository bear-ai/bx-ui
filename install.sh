#!/bin/bash

set -o pipefail
umask 077

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}未检测到系统版本，请联系脚本作者！${plain}\n" && exit 1
fi

arch=$(arch)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="amd64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64"
elif [[ $arch == "s390x" ]]; then
    arch="s390x"
else
    arch="amd64"
    echo -e "${red}检测架构失败，使用默认架构: ${arch}${plain}"
fi

echo "架构: ${arch}"

if [ $(getconf WORD_BIT) != '32' ] && [ $(getconf LONG_BIT) != '64' ]; then
    echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
    exit -1
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}请使用 CentOS 7 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n" && exit 1
    fi
fi

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install wget curl tar -y
    else
        apt install wget curl tar -y
    fi
}

# A newer installer may briefly see an older "latest" release. Do not install
# its unprivileged service together with root-only data directory permissions.
validate_root_service_archive() {
    local service_contents
    if ! service_contents=$(tar -xOf "$1" x-ui/x-ui.service 2>/dev/null); then
        echo "无法读取安装包中的服务配置，已停止安装，未停止现有面板。" >&2
        return 1
    fi
    if ! printf '%s\n' "${service_contents}" | awk '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            next
        }
        section == "[Service]" && /^[[:space:]]*(User|Group)[[:space:]]*=/ {
            key = $0
            sub(/=.*/, "", key)
            gsub(/[[:space:]]/, "", key)
            value = $0
            sub(/^[^=]*=/, "", value)
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            if (key == "User") user = value
            if (key == "Group") group = value
        }
        END { exit !(user == "root" && group == "root") }
    '; then
        echo "该安装包不是 root 默认运行版本，请选择 0.4.8 或更新版本；已停止安装，未停止现有面板。" >&2
        return 1
    fi
}

# Version 0.4.7 generated this exact override for the former unprivileged
# service. It would continue to restrict the new root service if left behind.
# Never remove a customized override or follow a symlink during migration.
migrate_legacy_tun_dropin() {
    local config_dir="${1:-/etc/systemd/system/x-ui.service.d}"
    local target="${config_dir}/50-bx-ui-tun.conf"
    if [[ -L "${config_dir}" || ( -e "${config_dir}" && ! -d "${config_dir}" ) ]]; then
        echo "服务配置目录不是普通目录：${config_dir}；请管理员检查后重试，未修改任何配置。" >&2
        return 1
    fi
    if [[ ! -e "${target}" && ! -L "${target}" ]]; then
        return 0
    fi
    if [[ -L "${target}" || ! -f "${target}" ]] || ! cmp -s -- "${target}" <(printf '%s\n' \
        '# Managed by bx-ui tun enable. Remove using bx-ui tun disable.' \
        '[Service]' \
        'PrivateDevices=false' \
        'DevicePolicy=closed' \
        'DeviceAllow=/dev/net/tun rw' \
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN' \
        'AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN'); then
        echo "检测到自定义 TUN 服务配置：${target}；此文件可能继续限制 root 权限，已保留。请先备份到 systemd 配置目录之外，确认其中的自定义设置后移走该文件，再重试安装。" >&2
        return 1
    fi
    # Check before stopping the old service; remove only after the new unit is installed.
    if [[ "${2:-}" == "--check" ]]; then
        return 0
    fi
    if ! rm -- "${target}"; then
        echo "无法移除旧版自动生成的 TUN 配置：${target}，请管理员检查后重试。" >&2
        return 1
    fi
    echo "已移除旧版自动生成的 TUN 权限配置，面板和 Xray 将使用 root 运行。"
}

# Keep this helper in sync with x-ui.sh. The binary owns the character/byte
# policy so Unicode passwords are checked identically in every entry point.
read_account_password() {
    local validation_status
    while true; do
        if ! IFS= read -rsp "请输入新密码（至少 8 个字符，UTF-8 编码后最多 72 字节）: " config_password; then
            echo >&2
            config_password=
            echo "输入已结束，已取消密码设置。" >&2
            return 1
        fi
        echo >&2
        if printf '%s\n' "${config_password}" | /usr/local/x-ui/x-ui setting -validate-password -password-stdin; then
            return 0
        else
            validation_status=$?
        fi
        config_password=
        if [[ ${validation_status} -ne 1 ]]; then
            echo "无法校验密码，请确认面板程序与安装脚本版本一致，已停止设置。" >&2
            return 1
        fi
        echo "密码不符合要求，请重新输入。" >&2
    done
}

# Configure the first installation without reporting a failed setting as saved.
config_after_install() {
    local config_confirm config_account config_password config_port
    echo -e "${yellow}出于安全考虑，安装/更新完成后需要强制修改端口与账户密码${plain}"
    if ! IFS= read -rp "确认是否继续?[y/n]: " config_confirm; then
        echo "输入已结束，已取消账户配置。" >&2
        return 1
    fi
    if [[ x"${config_confirm}" == x"y" || x"${config_confirm}" == x"Y" ]]; then
        if ! read -rp "请设置您的账户名:" config_account; then
            echo "输入已结束，已取消账户配置。" >&2
            return 1
        fi
        echo -e "${yellow}您的账户名将设定为:${config_account}${plain}"
        read_account_password || return 1
        if ! IFS= read -rp "请设置面板访问端口:" config_port; then
            config_password=
            echo "输入已结束，已取消账户配置。" >&2
            return 1
        fi
        echo -e "${yellow}您的面板访问端口将设定为:${config_port}${plain}"
        echo -e "${yellow}确认设定,设定中${plain}"
        if ! printf '%s\n' "${config_password}" | /usr/local/x-ui/x-ui setting -username "${config_account}" -password-stdin; then
            config_password=
            echo "账户密码设置失败，已停止安装配置，请检查错误后重试。" >&2
            return 1
        fi
        config_password=
        echo -e "${yellow}账户密码设定完成${plain}"
        if ! /usr/local/x-ui/x-ui setting -port "${config_port}"; then
            echo "面板端口设置失败，已停止安装配置，请检查错误后重试。" >&2
            return 1
        fi
        echo -e "${yellow}面板端口设定完成${plain}"
    else
        echo -e "${red}已取消,所有设置项均为默认设置,请及时修改${plain}"
    fi
}

install_x-ui() {
    local is_upgrade=false
    if [[ -s /etc/x-ui/x-ui.db ]]; then
        is_upgrade=true
        echo -e "${yellow}检测到现有数据库，本次升级将保留面板账号、端口和入站配置${plain}"
    fi

    cd /usr/local/ || exit 1

    if [[ $# -eq 0 ]]; then
		last_version=$(curl --proto '=https' --tlsv1.2 -fLsS "https://api.github.com/repos/bear-ai/bx-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}检测 x-ui 版本失败，可能是超出 Github API 限制，请稍后再试，或手动指定 x-ui 版本安装${plain}"
            exit 1
        fi
        echo -e "检测到 x-ui 最新版本：${last_version}，开始安装"
    else
        last_version=$1
        echo -e "开始安装 x-ui v$1"
    fi
	if [[ ! "${last_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo -e "${red}版本号格式无效${plain}"
		exit 1
	fi

    archive="x-ui-linux-${arch}.tar.gz"
    url="https://github.com/bear-ai/bx-ui/releases/download/${last_version}/${archive}"
	if ! wget --https-only -N -O "/usr/local/${archive}" "${url}"; then
        echo -e "${red}下载 x-ui ${last_version} 失败，请确认版本和服务器到 Github 的网络${plain}"
        exit 1
    fi
	if ! wget --https-only -N -O "/usr/local/${archive}.sha256" "${url}.sha256"; then
        echo -e "${red}下载校验文件失败，已停止安装${plain}"
        exit 1
    fi
    if ! sha256sum -c "${archive}.sha256"; then
        echo -e "${red}安装包 SHA-256 校验失败，已停止安装${plain}"
        exit 1
    fi

    validate_root_service_archive "${archive}" || exit 1
    migrate_legacy_tun_dropin /etc/systemd/system/x-ui.service.d --check || exit 1
    if ! systemctl stop x-ui; then
        if [[ "$(systemctl show x-ui.service --property=LoadState 2>/dev/null)" != "LoadState=not-found" ]]; then
            echo "无法停止现有面板，已中止安装，未替换程序。" >&2
            exit 1
        fi
    fi

    if [[ -e /usr/local/x-ui/ ]]; then
		rm -rf -- /usr/local/x-ui/ || exit 1
    fi

    # Never restore the CI builder's UID or permissive archive modes before
    # executing files as root. The process umask is 077 until ownership/modes
    # are deliberately normalized below.
    tar --no-same-owner --no-same-permissions -zxvf "${archive}" || exit 1
    rm "${archive}" "${archive}.sha256"
	install -d -m 0700 /etc/x-ui
	if [[ -f /etc/x-ui/x-ui.db ]]; then
		chmod 0600 /etc/x-ui/x-ui.db
    fi
    cd x-ui || exit 1
    chown -R root:root /usr/local/x-ui /etc/x-ui || exit 1
    find /usr/local/x-ui -type d -exec chmod 0755 {} + || exit 1
    find /usr/local/x-ui -type f -exec chmod go-w {} + || exit 1
    chmod 0755 x-ui x-ui.sh x-ui-update-guard install.sh "bin/xray-linux-${arch}" || exit 1
    install -o root -g root -m 0644 x-ui.service /etc/systemd/system/x-ui.service || exit 1
    migrate_legacy_tun_dropin || exit 1
    install -o root -g root -m 0755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui || exit 1
    if [[ "${is_upgrade}" == "false" ]]; then
        config_after_install || exit 1
    else
        echo -e "${green}现有面板配置已保留${plain}"
    fi
	chown -R root:root /etc/x-ui || exit 1
	find /etc/x-ui -type d -exec chmod 0700 {} + || exit 1
	find /etc/x-ui -type f -exec chmod 0600 {} + || exit 1
    systemctl daemon-reload || exit 1
    systemctl enable x-ui || exit 1
    systemctl start x-ui || exit 1
    echo -e "${green}x-ui v${last_version}${plain} 安装完成，面板已启动，"
    echo -e ""
    echo -e "x-ui 管理脚本使用方法: "
    echo -e "----------------------------------------------"
    echo -e "x-ui              - 显示管理菜单 (功能更多)"
    echo -e "x-ui start        - 启动 x-ui 面板"
    echo -e "x-ui stop         - 停止 x-ui 面板"
    echo -e "x-ui restart      - 重启 x-ui 面板"
    echo -e "x-ui status       - 查看 x-ui 状态"
    echo -e "x-ui enable       - 设置 x-ui 开机自启"
    echo -e "x-ui disable      - 取消 x-ui 开机自启"
    echo -e "x-ui log          - 查看 x-ui 日志"
    echo -e "x-ui v2-ui        - 迁移本机器的 v2-ui 账号数据至 x-ui"
    echo -e "x-ui update       - 更新 x-ui 面板"
    echo -e "x-ui install      - 安装 x-ui 面板"
    echo -e "x-ui uninstall    - 卸载 x-ui 面板"
    echo -e "----------------------------------------------"
}

echo -e "${green}开始安装${plain}"
install_base
if [[ $# -gt 0 ]]; then
	install_x-ui "$1"
else
	install_x-ui
fi

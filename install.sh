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

#This function will be called when user installed x-ui out of sercurity
config_after_install() {
    echo -e "${yellow}出于安全考虑，安装/更新完成后需要强制修改端口与账户密码${plain}"
    read -p "确认是否继续?[y/n]": config_confirm
    if [[ x"${config_confirm}" == x"y" || x"${config_confirm}" == x"Y" ]]; then
        read -p "请设置您的账户名:" config_account
        echo -e "${yellow}您的账户名将设定为:${config_account}${plain}"
		read -rsp "请设置您的账户密码:" config_password
		echo
        read -p "请设置面板访问端口:" config_port
        echo -e "${yellow}您的面板访问端口将设定为:${config_port}${plain}"
        echo -e "${yellow}确认设定,设定中${plain}"
		printf '%s\n' "${config_password}" | /usr/local/x-ui/x-ui setting -username "${config_account}" -password-stdin
        echo -e "${yellow}账户密码设定完成${plain}"
		/usr/local/x-ui/x-ui setting -port "${config_port}"
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

    cd /usr/local/

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

    systemctl stop x-ui

    if [[ -e /usr/local/x-ui/ ]]; then
		rm -rf -- /usr/local/x-ui/
    fi

    tar zxvf "${archive}"
    rm "${archive}" "${archive}.sha256"
	install -d -m 0700 /etc/x-ui
	if [[ -f /etc/x-ui/x-ui.db ]]; then
		chmod 0600 /etc/x-ui/x-ui.db
	fi
    cd x-ui
    chmod +x x-ui x-ui-update-guard bin/xray-linux-${arch}
	if ! getent group x-ui >/dev/null; then
		groupadd --system x-ui
	fi
	if ! id -u x-ui >/dev/null 2>&1; then
		useradd --system --gid x-ui --home-dir /nonexistent --shell /usr/sbin/nologin x-ui
	fi
	chown root:x-ui /usr/local/x-ui
	chmod 0775 /usr/local/x-ui
	chown root:x-ui /usr/local/x-ui/x-ui /usr/local/x-ui/x-ui.sh /usr/local/x-ui/x-ui-update-guard /usr/local/x-ui/x-ui.service
	chown -R x-ui:x-ui /etc/x-ui /usr/local/x-ui/bin
    cp -f x-ui.service /etc/systemd/system/
	install -m 0755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
    chmod +x /usr/local/x-ui/x-ui.sh
    chmod +x /usr/bin/x-ui
    if [[ "${is_upgrade}" == "false" ]]; then
        config_after_install
    else
        echo -e "${green}现有面板配置已保留${plain}"
    fi
	chown -R x-ui:x-ui /etc/x-ui
	find /etc/x-ui -type d -exec chmod 0700 {} +
	find /etc/x-ui -type f -exec chmod 0600 {} +
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui
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

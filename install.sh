#!/bin/bash
# ==========================================
# Oracle Cloud ARM 抢机助手 一键部署脚本
# 源项目: https://github.com/2019xuanying/oci-starts
# ==========================================

# 环境变量设置
REPO_URL="https://raw.githubusercontent.com/2019xuanying/oci-starts/main/oracle_sniper_web.py"
SCRIPT_DIR="/root/oci-starts"
SCRIPT_PATH="$SCRIPT_DIR/oracle_sniper_web.py"
SERVICE_PATH="/etc/systemd/system/oracle-sniper.service"

# 颜色设置
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"

echo -e "${GREEN}==================================================${RESET}"
echo -e "${GREEN}  Oracle Cloud ARM 抢机助手 一键部署脚本${RESET}"
echo -e "${GREEN}  GitHub: https://github.com/2019xuanying/oci-starts${RESET}"
echo -e "${GREEN}==================================================${RESET}"

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[错误] 请使用 root 权限运行此脚本。(比如: sudo bash install.sh)${RESET}"
  exit 1
fi

# 2. 安装系统依赖
echo -e "${YELLOW}[1/6] 正在更新系统并安装必要依赖...${RESET}"
if [ -f /etc/debian_version ]; then
    apt-get update -y
    apt-get install -y python3 python3-pip wget curl iptables ufw
elif [ -f /etc/redhat-release ]; then
    yum makecache
    yum install -y python3 python3-pip wget curl iptables firewalld
else
    echo -e "${RED}[错误] 不支持的操作系统，请使用 Ubuntu/Debian 或 CentOS/Oracle Linux。${RESET}"
    exit 1
fi

# 3. 安装 Python 依赖包
echo -e "${YELLOW}[2/6] 正在安装 Python 依赖 (Flask, OCI, Requests)...${RESET}"
# 兼容新版本 Linux(如 Debian 12 / Ubuntu 24.04)的 PEP 668 保护机制
pip3 install flask oci requests || pip3 install flask oci requests --break-system-packages

# 4. 下载核心脚本
echo -e "${YELLOW}[3/6] 正在从 GitHub 下载抢机助手脚本...${RESET}"
mkdir -p "$SCRIPT_DIR"
wget -O "$SCRIPT_PATH" "$REPO_URL"

if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "${RED}[错误] 下载失败，请检查服务器网络或对 GitHub 的访问情况。${RESET}"
    exit 1
fi

# 5. 配置防火墙放行 5000 端口
echo -e "${YELLOW}[4/6] 正在配置系统防火墙，放行 5000 端口...${RESET}"
# 放行 UFW
if command -v ufw >/dev/null 2>&1; then
    ufw allow 5000/tcp >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
fi
# 放行 Firewalld
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=5000/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
fi
# 放行 iptables
iptables -I INPUT -p tcp --dport 5000 -j ACCEPT >/dev/null 2>&1
iptables-save > /dev/null 2>&1

# 6. 配置 Systemd 守护进程
echo -e "${YELLOW}[5/6] 正在配置系统服务及开机自启...${RESET}"
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Oracle Cloud Sniper Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/python3 $SCRIPT_PATH
Restart=always
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable oracle-sniper
systemctl restart oracle-sniper

# 7. 获取公网 IP 显示结果
IP=$(curl -s -4 icanhazip.com || curl -s -4 ifconfig.me)

echo -e "${YELLOW}[6/6] 部署全部完成！${RESET}"
echo -e "${GREEN}==================================================${RESET}"
echo -e "✅ 面板访问地址: ${GREEN}http://$IP:5000${RESET}"
echo -e "✅ 默认管理员密码: ${YELLOW}admin${RESET}"
echo -e ""
echo -e "【常用管理命令】"
echo -e "   - 查看运行状态: systemctl status oracle-sniper"
echo -e "   - 重启面板服务: systemctl restart oracle-sniper"
echo -e "   - 停止面板服务: systemctl stop oracle-sniper"
echo -e "   - 查看运行日志: journalctl -u oracle-sniper -f"
echo -e ""
echo -e "${RED}[非常重要提示]${RESET} 请务必确保你在甲骨文云后台 VCN 的【安全列表(Security Lists)】中，也添加了目标端口为 5000 的 TCP 入站规则，否则网页将无法访问！"
echo -e "${GREEN}==================================================${RESET}"

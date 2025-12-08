# -*- coding: utf-8 -*-
"""
Oracle Cloud ARM Sniper with Web Panel (Pro Plus)
集成 Web 面板、main.tf 自动解析、配置持久化、自定义启动脚本、代理支持与日志轮转。

更新日志:
- [新增] 配置持久化 (sniper_config.json)
- [新增] 自定义 Cloud-Init 启动脚本
- [新增] 网络代理支持 (HTTP/SOCKS5)
- [新增] 本地日志文件轮转 (sniper.log)
- [修复] 兼容各版本 OCI SDK 签名

依赖安装:
pip3 install flask oci requests
"""

import os
import sys
import time
import json
import logging
import logging.handlers
import threading
import queue
import random
import base64
import requests
import re
from datetime import datetime
from functools import wraps

# Flask & OCI Imports
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
import oci
from oci.core import ComputeClient, VirtualNetworkClient

# ==========================================
# 全局配置 & 常量
# ==========================================
WEB_PORT = 5000
WEB_PASSWORD = "admin"  # 面板登录密码 (建议修改)
SECRET_KEY = os.urandom(24)
CONFIG_FILE = "sniper_config.json"
LOG_FILE = "sniper.log"

# ==========================================
# 日志系统初始化 (带轮转)
# ==========================================
log_queue = queue.Queue(maxsize=1000)

# 配置根日志记录器
logger = logging.getLogger('OracleSniper')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# 1. 文件处理器 (5MB x 3个文件)
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 2. 控制台处理器
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

def log_msg(msg, level="INFO"):
    """统一日志入口"""
    # 写入 Python logging 系统 (文件+控制台)
    if level == "ERROR":
        logger.error(msg)
    elif level == "WARNING":
        logger.warning(msg)
    elif level == "SUCCESS":
        logger.info(f"[SUCCESS] {msg}") # 用 INFO 级别记录成功
    else:
        logger.info(msg)
    
    # 推送至 Web 前端队列
    timestamp = datetime.now().strftime("%H:%M:%S")
    try:
        log_queue.put({"time": timestamp, "level": level, "message": msg}, block=False)
    except queue.Full:
        pass

# ==========================================
# 状态与配置管理 (持久化)
# ==========================================

class SniperState:
    def __init__(self):
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None
        self.stats = {
            "attempts": 0,
            "success": False,
            "last_status": "就绪",
            "current_delay": 0,
            "public_ip": "等待获取...",
            "start_time": None
        }
        self.config = self.load_config()

    def get_default_config(self):
        return {
            "oci": {
                "user": "",
                "fingerprint": "",
                "tenancy": "",
                "region": "",
                "key_content": ""
            },
            "instance": {
                "display_name": "Oracle-ARM-Server",
                "availability_domain": "",
                "subnet_id": "",
                "image_id": "",
                "ssh_key": "",
                "ocpus": 4,
                "memory_in_gbs": 24,
                "disk_size": 50,
                "user_data": "" # 自定义启动脚本
            },
            "strategy": {
                "min_interval": 15,
                "max_interval": 60
            },
            "proxy": {
                "enabled": False,
                "url": "" # e.g., http://127.0.0.1:7890
            },
            "telegram": {
                "enabled": False,
                "token": "",
                "chat_id": ""
            }
        }

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    # 深度合并默认配置，防止新版本缺少字段
                    default = self.get_default_config()
                    for section in default:
                        if section not in saved:
                            saved[section] = default[section]
                        else:
                            for key in default[section]:
                                if key not in saved[section]:
                                    saved[section][key] = default[section][key]
                    return saved
            except Exception as e:
                log_msg(f"加载配置文件失败: {str(e)}，使用默认配置", "WARNING")
        return self.get_default_config()

    def save_config(self, new_config):
        self.config = new_config
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            log_msg("配置已保存到本地文件", "INFO")
        except Exception as e:
            log_msg(f"保存配置文件失败: {str(e)}", "ERROR")

sniper_state = SniperState()

# ==========================================
# 辅助函数
# ==========================================

def telegram_notify(message, config):
    if not config['enabled'] or not config['token'] or not config['chat_id']:
        return
    
    # Telegram 通知也走代理 (如果设置了全局环境)
    url = f"https://api.telegram.org/bot{config['token']}/sendMessage"
    data = {"chat_id": config['chat_id'], "text": f"🐢 甲骨文抢机播报 🐢\n\n{message}", "parse_mode": "Markdown"}
    try:
        requests.post(url, data=data, timeout=10)
    except Exception as e:
        log_msg(f"Telegram 推送失败: {str(e)}", "ERROR")

def parse_terraform_file(content):
    """解析 main.tf 文件内容"""
    data = {}
    try:
        patterns = {
            'availability_domain': r'availability_domain\s*=\s*"(.*)"',
            'subnet_id': r'subnet_id\s*=\s*"(.*)"',
            'source_id': r'source_id\s*=\s*"(.*)"',
            'ocpus': r'ocpus\s*=\s*"?([\d\.]+)"?',
            'memory_in_gbs': r'memory_in_gbs\s*=\s*"?([\d\.]+)"?',
            'boot_volume_size_in_gbs': r'boot_volume_size_in_gbs\s*=\s*"?(\d+)"?',
            'ssh_authorized_keys': r'"ssh_authorized_keys"\s*=\s*"(.*)"',
            'display_name': r'display_name\s*=\s*"(.*)"'
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                val = match.group(1)
                if key == 'source_id': data['image_id'] = val
                elif key == 'boot_volume_size_in_gbs': data['disk_size'] = val
                elif key == 'ssh_authorized_keys': data['ssh_key'] = val
                else: data[key] = val
        return data
    except Exception as e:
        log_msg(f"TF 解析失败: {str(e)}", "ERROR")
        return None

# ==========================================
# 核心抢机逻辑
# ==========================================

class OracleSniper:
    def __init__(self, state):
        self.state = state
        self.oci_config = state.config['oci']
        self.ins_config = state.config['instance']
        
        if 'display_name' not in self.ins_config or not self.ins_config['display_name']:
            self.ins_config['display_name'] = "Oracle-ARM-Server"
            
        self.tg_config = state.config['telegram']
        self.proxy_config = state.config.get('proxy', {'enabled': False, 'url': ''})
        
        strategy = state.config.get('strategy', {})
        self.base_delay = float(strategy.get('min_interval', 15))
        self.max_delay = float(strategy.get('max_interval', 120))
        self.backoff_factor = 1.5
        self.deep_sleep_threshold = 2000
        self.deep_sleep_duration = 600

        # 设置代理
        self._setup_proxy()

        try:
            config_dict = {
                "user": self.oci_config['user'],
                "fingerprint": self.oci_config['fingerprint'],
                "tenancy": self.oci_config['tenancy'],
                "region": self.oci_config['region'],
                "key_content": self.oci_config['key_content']
            }
            for k, v in config_dict.items():
                if not v: raise ValueError(f"缺少 OCI 配置项: {k}")

            self.signer = oci.Signer(
                tenancy=self.oci_config['tenancy'],
                user=self.oci_config['user'],
                fingerprint=self.oci_config['fingerprint'],
                private_key_file_location=None, 
                private_key_content=self.oci_config['key_content']
            )
            
            # OCI 客户端会自动读取环境变量中的 HTTP_PROXY / HTTPS_PROXY
            self.compute_client = ComputeClient(config=config_dict, signer=self.signer)
            self.network_client = VirtualNetworkClient(config=config_dict, signer=self.signer)
            log_msg("OCI 客户端初始化成功", "SUCCESS")
        except Exception as e:
            log_msg(f"OCI 初始化失败: {str(e)}", "ERROR")
            raise e

    def _setup_proxy(self):
        """配置环境变量代理，影响 requests 和 OCI SDK"""
        if self.proxy_config['enabled'] and self.proxy_config['url']:
            proxy_url = self.proxy_config['url']
            os.environ['HTTP_PROXY'] = proxy_url
            os.environ['HTTPS_PROXY'] = proxy_url
            log_msg(f"已启用代理: {proxy_url}", "WARNING")
        else:
            # 清理代理环境变量，防止干扰
            os.environ.pop('HTTP_PROXY', None)
            os.environ.pop('HTTPS_PROXY', None)

    def prepare_userdata(self):
        """准备 Cloud-Init 脚本"""
        custom_script = self.ins_config.get('user_data', '').strip()
        
        if custom_script:
            log_msg("使用自定义 Cloud-Init 脚本启动", "INFO")
            # 直接使用用户提供的脚本，需进行 Base64 编码
            return base64.b64encode(custom_script.encode('utf-8')).decode('utf-8'), "由脚本控制"
        else:
            # 默认逻辑：生成随机密码
            passwd = ''.join(random.sample('ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba#@1234567890', 13))
            log_msg(f"使用自动生成的 Root 密码: {passwd}", "INFO")
            sh_script = f"""#!/bin/bash
echo root:{passwd} | sudo chpasswd root
sudo sed -i 's/^.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
sudo sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
sudo reboot
"""
            return base64.b64encode(sh_script.encode('utf-8')).decode('utf-8'), passwd

    def check_public_ip(self, instance_id):
        log_msg("正在获取公网 IP...", "INFO")
        for _ in range(20):
            try:
                vnic_attachments = self.compute_client.list_vnic_attachments(
                    compartment_id=self.oci_config['tenancy'],
                    instance_id=instance_id
                ).data
                if vnic_attachments:
                    vnic_id = vnic_attachments[0].vnic_id
                    vnic = self.network_client.get_vnic(vnic_id).data
                    if vnic.public_ip: return vnic.public_ip
            except Exception:
                pass
            time.sleep(5)
        return "获取超时"

    def run(self):
        target_name = self.ins_config.get('display_name', 'Oracle-ARM-Server')
        log_msg(f"🚀 任务启动 (间隔: {self.base_delay}s, 目标: {target_name})...", "INFO")
        telegram_notify(f"脚本已启动\n目标: {target_name}", self.tg_config)
        
        user_data_b64, root_pwd_or_msg = self.prepare_userdata()
        
        current_delay = self.base_delay
        backoff_attempt = 0
        capacity_error_count = 0
        self.state.stats['start_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        while not self.state.stop_event.is_set():
            jitter = random.uniform(1.0, 3.0)
            actual_wait = current_delay + jitter
            self.state.stats['current_delay'] = f"{actual_wait:.2f}s"
            
            try:
                launch_details = oci.core.models.LaunchInstanceDetails(
                    display_name=target_name,
                    compartment_id=self.oci_config['tenancy'],
                    shape="VM.Standard.A1.Flex",
                    shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                        ocpus=float(self.ins_config['ocpus']),
                        memory_in_gbs=float(self.ins_config['memory_in_gbs'])
                    ),
                    availability_domain=self.ins_config['availability_domain'],
                    create_vnic_details=oci.core.models.CreateVnicDetails(
                        subnet_id=self.ins_config['subnet_id'],
                        hostname_label=target_name.lower().replace(" ", "-")[:15]
                    ),
                    source_details=oci.core.models.InstanceSourceViaImageDetails(
                        image_id=self.ins_config['image_id'],
                        boot_volume_size_in_gbs=int(self.ins_config['disk_size'])
                    ),
                    metadata={
                        "ssh_authorized_keys": self.ins_config['ssh_key'],
                        "user_data": user_data_b64
                    }
                )

                response = self.compute_client.launch_instance(launch_details)
                instance = response.data
                
                self.state.stats['success'] = True
                self.state.stats['last_status'] = "成功！"
                self.state.stats['attempts'] += 1
                
                log_msg(f"🎉 抢注成功! Instance ID: {instance.id}", "SUCCESS")
                public_ip = self.check_public_ip(instance.id)
                self.state.stats['public_ip'] = public_ip
                
                final_report = f"🎉 抢注成功!\nIP: {public_ip}\nRoot信息: {root_pwd_or_msg}\n请尽快检查!"
                log_msg(f"IP: {public_ip}", "SUCCESS")
                telegram_notify(final_report, self.tg_config)
                self.state.running = False
                break

            except oci.exceptions.ServiceError as e:
                self.state.stats['attempts'] += 1
                
                if e.status == 429:
                    backoff_attempt += 1
                    calculated_delay = self.base_delay * (self.backoff_factor ** backoff_attempt)
                    current_delay = min(calculated_delay, self.max_delay)
                    self.state.stats['last_status'] = "429 请求过多"
                    log_msg(f"⚠️ 请求限速 (429). 暂停 {current_delay:.1f}s 后重试", "WARNING")
                
                elif e.status == 500 and 'Out of host capacity' in str(e.message):
                    capacity_error_count += 1
                    backoff_attempt = 0
                    current_delay = self.base_delay 
                    self.state.stats['last_status'] = "库存不足 (500)"
                    if capacity_error_count % 10 == 0:
                        log_msg(f"⏳ 库存不足 (已尝试 {capacity_error_count} 次)", "INFO")

                    if capacity_error_count >= self.deep_sleep_threshold:
                        sleep_msg = f"😴 连续失败过多，进入深度休眠 ({self.deep_sleep_duration/60:.1f} 分钟)..."
                        log_msg(sleep_msg, "WARNING")
                        telegram_notify(sleep_msg, self.tg_config)
                        for _ in range(int(self.deep_sleep_duration)):
                            if self.state.stop_event.is_set(): return
                            time.sleep(1)
                        capacity_error_count = 0
                        actual_wait = 0 
                else:
                    err_msg = str(e.message)
                    self.state.stats['last_status'] = f"错误: {e.status}"
                    if "Service limit" in err_msg and e.status == 400:
                        log_msg(f"❌ 配额不足停止: {err_msg}", "ERROR")
                        self.state.running = False
                        break
                    else:
                        log_msg(f"❌ API 错误: {e.status} - {err_msg}", "ERROR")
            
            except Exception as e:
                log_msg(f"❌ 系统错误: {str(e)}", "ERROR")
                self.state.running = False
                break
            
            if actual_wait > 0: time.sleep(actual_wait)

# ==========================================
# Flask App
# ==========================================

app = Flask(__name__)
app.secret_key = SECRET_KEY

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# HTML 模板 (包含新字段)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oracle Cloud 抢机助手</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8fafc; color: #334155; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
        .card { background-color: #ffffff; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06); border-radius: 0.5rem; }
        .input-light { background-color: #ffffff; border: 1px solid #cbd5e1; color: #1e293b; transition: all 0.2s; }
        .input-light:focus { border-color: #3b82f6; ring: 2px solid #3b82f6; outline: none; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
        .log-box { height: 350px; overflow-y: scroll; font-size: 0.85rem; background-color: #f1f5f9; border: 1px solid #e2e8f0; color: #334155; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
    </style>
</head>
<body class="min-h-screen flex flex-col">

{% if not logged_in %}
<div class="flex items-center justify-center flex-grow bg-gray-50">
    <div class="card p-8 w-96">
        <h1 class="text-2xl font-bold mb-6 text-center text-blue-600"><i class="fas fa-cloud mr-2"></i>系统登录</h1>
        <form method="POST" action="/login">
            <input type="password" name="password" placeholder="请输入密码" class="w-full p-2.5 rounded mb-6 input-light">
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2.5 px-4 rounded transition shadow-sm">登 录</button>
        </form>
    </div>
</div>
{% else %}

<nav class="bg-white border-b border-gray-200 px-6 py-3 sticky top-0 z-50 shadow-sm">
    <div class="container mx-auto flex justify-between items-center">
        <div class="flex items-center gap-3">
             <div class="text-xl font-bold text-blue-600"><i class="fas fa-server mr-2"></i>Oracle Sniper</div>
             <span class="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full font-medium">Pro+</span>
        </div>
        <div class="flex items-center gap-4">
            <span id="status-badge" class="px-3 py-1 rounded-full text-sm font-bold bg-gray-200 text-gray-600">空闲中</span>
            <a href="/logout" class="text-gray-500 hover:text-red-500 transition"><i class="fas fa-sign-out-alt text-lg"></i></a>
        </div>
    </div>
</nav>

<div class="container mx-auto p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 flex-grow">
    <!-- 左侧配置栏 -->
    <div class="lg:col-span-1 space-y-6">
        
        <!-- OCI 凭证 -->
        <div class="card p-5">
            <h2 class="text-lg font-bold mb-4 text-gray-800 border-b pb-2"><i class="fas fa-id-card mr-2 text-blue-500"></i>OCI API 凭证</h2>
            <form id="config-form" class="space-y-4">
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">User OCID</label><input type="text" name="user" class="w-full p-2 rounded input-light text-sm" value="{{ config.oci.user }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Tenancy OCID</label><input type="text" name="tenancy" class="w-full p-2 rounded input-light text-sm" value="{{ config.oci.tenancy }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Region</label><input type="text" name="region" class="w-full p-2 rounded input-light text-sm" value="{{ config.oci.region }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Fingerprint</label><input type="text" name="fingerprint" class="w-full p-2 rounded input-light text-sm" value="{{ config.oci.fingerprint }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Private Key (PEM内容)</label><textarea name="key_content" rows="3" class="w-full p-2 rounded input-light text-xs font-mono">{{ config.oci.key_content }}</textarea></div>
            </form>
        </div>

        <!-- 实例配置 -->
        <div class="card p-5 relative">
            <div class="flex justify-between items-center mb-4 border-b pb-2">
                <h2 class="text-lg font-bold text-gray-800"><i class="fas fa-cogs mr-2 text-purple-500"></i>实例配置</h2>
                <div class="relative">
                    <input type="file" id="tf-upload" class="hidden" onchange="uploadTfFile()">
                    <label for="tf-upload" class="cursor-pointer bg-purple-100 hover:bg-purple-200 text-purple-700 text-xs px-3 py-1.5 rounded font-medium transition flex items-center">
                        <i class="fas fa-file-upload mr-1.5"></i> 上传 main.tf
                    </label>
                </div>
            </div>

            <form id="instance-form" class="space-y-4">
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">实例名称 (Display Name)</label><input type="text" name="display_name" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.display_name }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Availability Domain</label><input type="text" id="inp_ad" name="availability_domain" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.availability_domain }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Subnet ID</label><input type="text" id="inp_subnet" name="subnet_id" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.subnet_id }}"></div>
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">Image ID</label><input type="text" id="inp_image" name="image_id" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.image_id }}"></div>
                
                <div class="grid grid-cols-3 gap-3">
                    <div><label class="block text-xs font-semibold text-gray-500 mb-1">OCPUs</label><input type="number" id="inp_cpu" name="ocpus" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.ocpus }}"></div>
                    <div><label class="block text-xs font-semibold text-gray-500 mb-1">内存(GB)</label><input type="number" id="inp_ram" name="memory_in_gbs" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.memory_in_gbs }}"></div>
                    <div><label class="block text-xs font-semibold text-gray-500 mb-1">硬盘(GB)</label><input type="number" id="inp_disk" name="disk_size" class="w-full p-2 rounded input-light text-sm" value="{{ config.instance.disk_size }}"></div>
                </div>
                
                <div><label class="block text-xs font-semibold text-gray-500 mb-1">SSH 公钥</label><textarea id="inp_ssh" name="ssh_key" rows="2" class="w-full p-2 rounded input-light text-xs font-mono">{{ config.instance.ssh_key }}</textarea></div>

                <!-- 自定义启动脚本 -->
                <div>
                    <label class="block text-xs font-semibold text-gray-500 mb-1">启动脚本 (User Data)</label>
                    <textarea name="user_data" rows="3" placeholder="留空则自动生成随机 Root 密码脚本。如需自定义（安装Docker等）请在此输入 Shell 脚本..." class="w-full p-2 rounded input-light text-xs font-mono bg-gray-50">{{ config.instance.user_data }}</textarea>
                </div>

                <!-- 策略与代理 -->
                <div class="pt-2 border-t mt-2 grid grid-cols-2 gap-4">
                     <div>
                        <label class="block text-xs font-semibold text-gray-500 mb-1">请求间隔 (秒)</label>
                        <input type="number" name="min_interval" id="strategy_interval" class="w-full p-1.5 rounded input-light text-center font-bold text-blue-600" value="{{ config.strategy.min_interval }}">
                     </div>
                </div>
            </form>
        </div>

        <!-- 代理 & 通知 -->
        <div class="card p-5">
            <h2 class="text-lg font-bold mb-4 text-gray-800 border-b pb-2"><i class="fas fa-network-wired mr-2 text-blue-400"></i>高级设置</h2>
            
            <form id="proxy-form" class="space-y-4 mb-4 border-b pb-4">
                 <div class="flex items-center mb-2">
                    <input type="checkbox" name="proxy_enabled" id="proxy_enabled" {% if config.proxy.enabled %}checked{% endif %} class="w-4 h-4 text-blue-600 border-gray-300 rounded">
                    <label for="proxy_enabled" class="ml-2 text-sm text-gray-700 font-bold">启用网络代理</label>
                </div>
                <div>
                    <input type="text" name="proxy_url" placeholder="http://127.0.0.1:7890 或 socks5://user:pass@host:port" class="w-full p-2 rounded input-light text-sm" value="{{ config.proxy.url }}">
                    <p class="text-xs text-gray-400 mt-1">支持 HTTP/HTTPS/SOCKS5，用于防止本地 IP 被风控。</p>
                </div>
            </form>

            <form id="tg-form" class="space-y-4">
                <div class="flex items-center mb-2">
                    <input type="checkbox" name="tg_enabled" id="tg_enabled" {% if config.telegram.enabled %}checked{% endif %} class="w-4 h-4 text-blue-600 border-gray-300 rounded">
                    <label for="tg_enabled" class="ml-2 text-sm text-gray-700">启用 Telegram 通知</label>
                </div>
                <div><input type="text" name="tg_token" placeholder="Bot Token" class="w-full p-2 rounded input-light text-sm" value="{{ config.telegram.token }}"></div>
                <div><input type="text" name="tg_chat_id" placeholder="Chat ID" class="w-full p-2 rounded input-light text-sm" value="{{ config.telegram.chat_id }}"></div>
            </form>
            
            <button onclick="saveConfig()" class="w-full mt-6 bg-slate-800 hover:bg-slate-900 text-white font-bold py-2.5 rounded transition shadow-lg flex items-center justify-center">
                <i class="fas fa-save mr-2"></i> 保存并应用配置
            </button>
        </div>
    </div>

    <!-- 右侧监控栏 -->
    <div class="lg:col-span-2 space-y-6 flex flex-col">
        <!-- 仪表盘 -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="card p-4 text-center border-b-4 border-blue-500">
                <div class="text-gray-400 text-xs font-bold uppercase tracking-wider">尝试次数</div>
                <div class="text-2xl font-black text-gray-800 mt-1" id="stat-attempts">0</div>
            </div>
            <div class="card p-4 text-center border-b-4 border-yellow-500">
                <div class="text-gray-400 text-xs font-bold uppercase tracking-wider">状态</div>
                <div class="text-lg font-bold text-yellow-600 truncate mt-1" id="stat-status">就绪</div>
            </div>
            <div class="card p-4 text-center border-b-4 border-purple-500">
                <div class="text-gray-400 text-xs font-bold uppercase tracking-wider">延迟</div>
                <div class="text-xl font-bold text-purple-600 mt-1" id="stat-delay">0s</div>
            </div>
             <div class="card p-4 text-center border-b-4 border-gray-500">
                <div class="text-gray-400 text-xs font-bold uppercase tracking-wider">开始时间</div>
                <div class="text-sm font-bold text-gray-600 mt-2" id="stat-start">--</div>
            </div>
        </div>

        <!-- 成功提示 -->
        <div id="success-card" class="hidden bg-green-50 border border-green-200 p-6 rounded-lg text-center shadow-sm">
            <h2 class="text-2xl font-bold text-green-700 mb-1">🎉 抢注成功!</h2>
            <p class="text-gray-600 mb-2">Public IP: <span class="font-mono font-bold text-green-800" id="success-ip">...</span></p>
        </div>

        <!-- 日志 -->
        <div class="card flex-grow flex flex-col overflow-hidden">
            <div class="bg-gray-50 px-4 py-3 border-b border-gray-200 flex justify-between items-center">
                <span class="text-sm font-bold text-gray-600"><i class="fas fa-terminal mr-2"></i>实时运行日志</span>
                <button onclick="clearLogs()" class="text-xs text-gray-400 hover:text-red-500 transition"><i class="fas fa-trash-alt mr-1"></i>清空</button>
            </div>
            <div id="log-container" class="log-box p-4 font-mono text-xs space-y-1.5 flex-grow">
                <div class="text-gray-400 italic">系统就绪，等待启动...</div>
            </div>
        </div>

        <!-- 控制按钮 -->
        <div class="grid grid-cols-2 gap-4 mt-auto">
            <button onclick="startSniper()" id="btn-start" class="bg-green-600 hover:bg-green-700 text-white font-bold py-4 rounded-lg text-lg transition shadow-xl shadow-green-200 flex items-center justify-center">
                <i class="fas fa-play mr-2"></i> 启动任务
            </button>
            <button onclick="stopSniper()" id="btn-stop" class="bg-red-500 hover:bg-red-600 text-white font-bold py-4 rounded-lg text-lg transition opacity-50 cursor-not-allowed flex items-center justify-center" disabled>
                <i class="fas fa-stop mr-2"></i> 停止任务
            </button>
        </div>
    </div>
</div>

<script>
    let isRunning = false;

    function uploadTfFile() {
        const input = document.getElementById('tf-upload');
        const file = input.files[0];
        if(!file) return;
        const formData = new FormData();
        formData.append('file', file);
        
        const label = input.nextElementSibling;
        const originalText = label.innerHTML;
        label.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> 解析中...';

        fetch('/api/upload_tf', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            label.innerHTML = originalText;
            if(data.status === 'ok') {
                const d = data.data;
                const fields = {
                    'inp_ad': d.availability_domain, 'inp_subnet': d.subnet_id, 'inp_image': d.image_id,
                    'inp_cpu': d.ocpus, 'inp_ram': d.memory_in_gbs, 'inp_disk': d.disk_size, 'inp_ssh': d.ssh_key
                };
                for (const [id, val] of Object.entries(fields)) {
                    if (val) document.getElementById(id).value = val;
                }
                if(d.display_name) document.querySelector('[name=display_name]').value = d.display_name;
                alert("✅ main.tf 解析成功！");
            } else {
                alert("❌ 解析失败: " + data.msg);
            }
        });
    }

    function saveConfig() {
        const config = {
            oci: Object.fromEntries(new FormData(document.getElementById('config-form'))),
            instance: Object.fromEntries(new FormData(document.getElementById('instance-form'))),
            strategy: { min_interval: document.getElementById('strategy_interval').value },
            proxy: {
                enabled: document.getElementById('proxy_enabled').checked,
                url: document.querySelector('[name=proxy_url]').value
            },
            telegram: {
                enabled: document.getElementById('tg_enabled').checked,
                token: document.querySelector('[name=tg_token]').value,
                chat_id: document.querySelector('[name=tg_chat_id]').value
            }
        };
        fetch('/api/config', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config)})
        .then(r => r.json()).then(d => alert("✅ " + d.msg));
    }

    function startSniper() {
        fetch('/api/start', {method: 'POST'}).then(r => r.json()).then(d => {
            if(d.status === 'error') alert("❌ " + d.msg);
            else updateUIState(true);
        });
    }

    function stopSniper() {
        fetch('/api/stop', {method: 'POST'}).then(() => updateUIState(false));
    }

    function updateUIState(running) {
        isRunning = running;
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const badge = document.getElementById('status-badge');

        btnStart.disabled = running;
        btnStart.classList.toggle('opacity-50', running);
        btnStart.classList.toggle('cursor-not-allowed', running);
        
        btnStop.disabled = !running;
        btnStop.classList.toggle('opacity-50', !running);
        btnStop.classList.toggle('cursor-not-allowed', !running);

        badge.innerText = running ? "运行中" : "已停止";
        badge.className = running ? "px-3 py-1 rounded-full text-sm font-bold bg-green-100 text-green-700 border border-green-200 animate-pulse" : "px-3 py-1 rounded-full text-sm font-bold bg-gray-200 text-gray-600";
    }

    setInterval(() => {
        fetch('/api/status').then(r => r.json()).then(data => {
            document.getElementById('stat-attempts').innerText = data.stats.attempts;
            document.getElementById('stat-status').innerText = data.stats.last_status;
            document.getElementById('stat-delay').innerText = data.stats.current_delay;
            document.getElementById('stat-start').innerText = data.stats.start_time || '--';
            
            if(data.running !== isRunning) updateUIState(data.running);
            if(data.stats.success) {
                document.getElementById('success-card').classList.remove('hidden');
                document.getElementById('success-ip').innerText = data.stats.public_ip;
            }
            
            const logContainer = document.getElementById('log-container');
            if(data.logs.length > 0) {
                data.logs.forEach(log => {
                    let colorClass = 'text-gray-600';
                    if(log.level === 'ERROR') colorClass = 'text-red-600 font-bold';
                    else if(log.level === 'SUCCESS') colorClass = 'text-green-600 font-bold';
                    else if(log.level === 'WARNING') colorClass = 'text-orange-500';
                    const div = document.createElement('div');
                    div.className = colorClass;
                    div.innerHTML = `<span class="text-gray-400 mr-2">[${log.time}]</span>${log.message}`;
                    logContainer.appendChild(div);
                });
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        });
    }, 2000);
    function clearLogs() { document.getElementById('log-container').innerHTML = ''; }
</script>
{% endif %}
</body>
</html>
"""

# ==========================================
# Flask 路由
# ==========================================

@app.route('/api/upload_tf', methods=['POST'])
@login_required
def upload_tf():
    if 'file' not in request.files:
        return jsonify({"status": "error", "msg": "No file uploaded"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "msg": "Empty filename"})
    
    try:
        content = file.read().decode('utf-8')
        parsed_data = parse_terraform_file(content)
        if parsed_data:
            return jsonify({"status": "ok", "data": parsed_data})
        else:
            return jsonify({"status": "error", "msg": "Could not parse main.tf"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route('/', methods=['GET'])
def index():
    if not session.get('logged_in'): return render_template_string(HTML_TEMPLATE, logged_in=False)
    # 确保 session 中的配置与后端同步
    return render_template_string(HTML_TEMPLATE, logged_in=True, config=sniper_state.config)

@app.route('/login', methods=['POST'])
def login():
    if request.form['password'] == WEB_PASSWORD: session['logged_in'] = True
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/api/config', methods=['POST'])
@login_required
def save_config_route():
    data = request.json
    # 更新内存中的配置
    sniper_state.config['oci'] = data.get('oci', sniper_state.config['oci'])
    sniper_state.config['instance'] = data.get('instance', sniper_state.config['instance'])
    sniper_state.config['telegram'] = data.get('telegram', sniper_state.config['telegram'])
    sniper_state.config['proxy'] = data.get('proxy', sniper_state.config.get('proxy', {}))
    
    if 'strategy' in data:
        sniper_state.config['strategy'] = data['strategy']
    
    # 触发持久化保存
    sniper_state.save_config(sniper_state.config)
    return jsonify({"status": "ok", "msg": "配置已保存到本地"})

@app.route('/api/start', methods=['POST'])
@login_required
def start_sniper():
    if sniper_state.running: return jsonify({"status": "error", "msg": "任务已经在运行中"})
    
    if not sniper_state.config['oci']['user'] or not sniper_state.config['oci']['key_content']:
         return jsonify({"status": "error", "msg": "请先填写 OCI 凭证信息"})
    
    sniper_state.stop_event.clear()
    sniper_state.running = True
    sniper_state.stats['success'] = False
    
    def run_wrapper():
        try:
            sniper = OracleSniper(sniper_state)
            sniper.run()
        except Exception as e:
            log_msg(f"启动失败: {str(e)}", "ERROR")
            sniper_state.running = False

    sniper_state.thread = threading.Thread(target=run_wrapper)
    sniper_state.thread.daemon = True
    sniper_state.thread.start()
    return jsonify({"status": "ok"})

@app.route('/api/stop', methods=['POST'])
@login_required
def stop_sniper():
    if sniper_state.running:
        sniper_state.stop_event.set()
        log_msg("正在停止任务...", "WARNING")
        time.sleep(1)
        if not sniper_state.thread.is_alive(): sniper_state.running = False
    return jsonify({"status": "ok"})

@app.route('/api/status')
@login_required
def get_status():
    logs = []
    try:
        while True: logs.append(log_queue.get_nowait())
    except queue.Empty: pass
    return jsonify({"running": sniper_state.running, "stats": sniper_state.stats, "logs": logs})

if __name__ == '__main__':
    print(f"[*] 面板地址: http://0.0.0.0:{WEB_PORT}")
    print(f"[*] 管理密码: {WEB_PASSWORD}")
    print(f"[*] 配置文件: {CONFIG_FILE}")
    print(f"[*] 日志文件: {LOG_FILE}")
    app.run(host='0.0.0.0', port=WEB_PORT, debug=False)

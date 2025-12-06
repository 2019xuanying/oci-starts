# -*- coding: utf-8 -*-
"""
Oracle Cloud ARM Instance Sniper with Web Panel
集成 Web 面板、参数配置、日志监控、退避算法与深度休眠功能的甲骨文抢机脚本。

依赖安装:
pip install flask oci requests
"""

import os
import sys
import time
import json
import logging
import threading
import queue
import random
import base64
import requests
from datetime import datetime
from functools import wraps

# Flask & OCI Imports
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
import oci
from oci.core import ComputeClient, VirtualNetworkClient

# ==========================================
# 全局配置 (可在此修改默认面板密码)
# ==========================================
WEB_PORT = 5000
WEB_PASSWORD = "admin"  # 面板登录密码
SECRET_KEY = os.urandom(24) # Session加密密钥

# ==========================================
# 抢机策略配置 (默认值，实际运行受Web端控制)
# ==========================================
DEFAULT_STRATEGY = {
    "base_delay": 15.0,      # 基础延时
    "max_delay": 120.0,      # 最大延时
    "backoff_factor": 1.5,   # 退避因子
    "deep_sleep_threshold": 2000, # 深度休眠触发阈值
    "deep_sleep_duration": 600    # 深度休眠时长(秒)
}

# ==========================================
# 全局状态存储
# ==========================================
# 消息队列，用于前端日志显示
log_queue = queue.Queue(maxsize=1000)

# 运行状态控制
class SniperState:
    def __init__(self):
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None
        self.stats = {
            "attempts": 0,
            "success": False,
            "last_status": "Ready",
            "current_delay": 0,
            "public_ip": "N/A",
            "start_time": None
        }
        # 存储配置信息
        self.config = {
            "oci": {
                "user": "",
                "fingerprint": "",
                "tenancy": "",
                "region": "",
                "key_content": ""  # 私钥内容
            },
            "instance": {
                "availability_domain": "",
                "subnet_id": "",
                "image_id": "",
                "ssh_key": "",
                "ocpus": 4,
                "memory_in_gbs": 24,
                "disk_size": 50,
                "display_name": "Oracle-ARM-Server"
            },
            "telegram": {
                "enabled": False,
                "token": "",
                "chat_id": ""
            }
        }

sniper_state = SniperState()

# ==========================================
# 辅助函数
# ==========================================

def log_msg(msg, level="INFO"):
    """记录日志并推送到队列"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] [{level}] {msg}"
    print(formatted_msg) # 控制台输出
    
    # 推送到队列供Web读取
    try:
        log_queue.put({
            "time": timestamp,
            "level": level,
            "message": msg
        }, block=False)
    except queue.Full:
        pass # 队列满则丢弃旧日志

def telegram_notify(message, config):
    """发送Telegram通知"""
    if not config['enabled'] or not config['token'] or not config['chat_id']:
        return
    
    url = f"https://api.telegram.org/bot{config['token']}/sendMessage"
    data = {
        "chat_id": config['chat_id'],
        "text": f"🐢 甲骨文抢机播报 🐢\n\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, data=data, timeout=10)
    except Exception as e:
        log_msg(f"Telegram 推送失败: {str(e)}", "ERROR")

# ==========================================
# 核心抢机逻辑类 (继承自用户提供的优化版)
# ==========================================

class OracleSniper:
    def __init__(self, state):
        self.state = state
        self.oci_config = state.config['oci']
        self.ins_config = state.config['instance']
        self.tg_config = state.config['telegram']
        
        # 策略参数
        self.base_delay = DEFAULT_STRATEGY['base_delay']
        self.max_delay = DEFAULT_STRATEGY['max_delay']
        self.backoff_factor = DEFAULT_STRATEGY['backoff_factor']
        self.deep_sleep_threshold = DEFAULT_STRATEGY['deep_sleep_threshold']
        self.deep_sleep_duration = DEFAULT_STRATEGY['deep_sleep_duration']

        # 初始化 OCI 客户端
        try:
            # 构造 OCI 配置字典
            config_dict = {
                "user": self.oci_config['user'],
                "fingerprint": self.oci_config['fingerprint'],
                "tenancy": self.oci_config['tenancy'],
                "region": self.oci_config['region'],
                "key_content": self.oci_config['key_content']
            }
            # 验证配置完整性
            for k, v in config_dict.items():
                if not v:
                    raise ValueError(f"缺少 OCI 配置项: {k}")

            # 使用 Signer 处理直接传入的私钥内容
            self.signer = oci.Signer(
                tenancy=self.oci_config['tenancy'],
                user=self.oci_config['user'],
                fingerprint=self.oci_config['fingerprint'],
                private_key_content=self.oci_config['key_content']
            )
            
            self.compute_client = ComputeClient(config=config_dict, signer=self.signer)
            self.network_client = VirtualNetworkClient(config=config_dict, signer=self.signer)
            
            log_msg("OCI 客户端初始化成功", "SUCCESS")
            
        except Exception as e:
            log_msg(f"OCI 初始化失败: {str(e)}", "ERROR")
            raise e

    def generate_userdata(self):
        """生成开机启动脚本 (修改Root密码)"""
        passwd = ''.join(random.sample('ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba#@1234567890', 13))
        log_msg(f"预生成 Root 密码: {passwd}", "INFO")
        
        sh_script = f"""#!/bin/bash
echo root:{passwd} | sudo chpasswd root
sudo sed -i 's/^.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
sudo sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
sudo reboot
"""
        return base64.b64encode(sh_script.encode('utf-8')).decode('utf-8'), passwd

    def check_public_ip(self, instance_id):
        """获取公网IP"""
        log_msg("正在获取公网 IP...", "INFO")
        for _ in range(20): # 尝试20次
            try:
                vnic_attachments = self.compute_client.list_vnic_attachments(
                    compartment_id=self.oci_config['tenancy'],
                    instance_id=instance_id
                ).data
                
                if vnic_attachments:
                    vnic_id = vnic_attachments[0].vnic_id
                    vnic = self.network_client.get_vnic(vnic_id).data
                    if vnic.public_ip:
                        return vnic.public_ip
            except Exception:
                pass
            time.sleep(5)
        return "获取超时"

    def run(self):
        log_msg("🚀 抢机任务已启动...", "INFO")
        telegram_notify(f"脚本已启动\n目标: {self.ins_config['display_name']}\n配置: {self.ins_config['ocpus']}C / {self.ins_config['memory_in_gbs']}G", self.tg_config)
        
        user_data, root_pwd = self.generate_userdata()
        
        current_delay = self.base_delay
        backoff_attempt = 0
        capacity_error_count = 0
        
        self.state.stats['start_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        while not self.state.stop_event.is_set():
            # 1. 增加随机抖动 (Jitter)
            jitter = random.uniform(2, 5)
            actual_wait = current_delay + jitter
            
            self.state.stats['current_delay'] = f"{actual_wait:.2f}s"
            
            try:
                # 2. 尝试创建实例
                launch_details = oci.core.models.LaunchInstanceDetails(
                    display_name=self.ins_config['display_name'],
                    compartment_id=self.oci_config['tenancy'],
                    shape="VM.Standard.A1.Flex",
                    shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                        ocpus=float(self.ins_config['ocpus']),
                        memory_in_gbs=float(self.ins_config['memory_in_gbs'])
                    ),
                    availability_domain=self.ins_config['availability_domain'],
                    create_vnic_details=oci.core.models.CreateVnicDetails(
                        subnet_id=self.ins_config['subnet_id'],
                        hostname_label=self.ins_config['display_name'].lower()
                    ),
                    source_details=oci.core.models.InstanceSourceViaImageDetails(
                        image_id=self.ins_config['image_id'],
                        boot_volume_size_in_gbs=int(self.ins_config['disk_size'])
                    ),
                    metadata={
                        "ssh_authorized_keys": self.ins_config['ssh_key'],
                        "user_data": user_data
                    }
                )

                response = self.compute_client.launch_instance(launch_details)
                
                # 3. 成功处理
                instance = response.data
                self.state.stats['success'] = True
                self.state.stats['last_status'] = "SUCCESS"
                self.state.stats['attempts'] += 1
                
                success_msg = f"🎉 抢注成功! Instance ID: {instance.id}"
                log_msg(success_msg, "SUCCESS")
                
                public_ip = self.check_public_ip(instance.id)
                self.state.stats['public_ip'] = public_ip
                
                final_report = f"🎉 抢注成功!\nIP: {public_ip}\nRoot密码: {root_pwd}\n请尽快登录修改密码!"
                log_msg(f"IP: {public_ip}", "SUCCESS")
                log_msg(f"Root密码: {root_pwd}", "SUCCESS")
                telegram_notify(final_report, self.tg_config)
                
                self.state.running = False
                break

            except oci.exceptions.ServiceError as e:
                self.state.stats['attempts'] += 1
                
                # 4. 错误处理逻辑
                if e.status == 429: # 限流
                    backoff_attempt += 1
                    calculated_delay = self.base_delay * (self.backoff_factor ** backoff_attempt)
                    current_delay = min(calculated_delay, self.max_delay)
                    self.state.stats['last_status'] = "429 Too Many Requests"
                    log_msg(f"⚠️ 请求限速 (429). 退避重试: {backoff_attempt}, 下次等待: {current_delay+jitter:.1f}s", "WARNING")
                
                elif e.status == 500 and 'Out of host capacity' in str(e.message): # 缺货
                    capacity_error_count += 1
                    backoff_attempt = 0 # 重置退避
                    current_delay = self.base_delay # 恢复基础延迟
                    self.state.stats['last_status'] = "Out of Capacity"
                    
                    if capacity_error_count % 10 == 0: # 减少刷屏
                        log_msg(f"⏳ 容量不足 (500). 连续次数: {capacity_error_count}", "INFO")

                    # 深度休眠检查
                    if capacity_error_count >= self.deep_sleep_threshold:
                        sleep_msg = f"😴 连续 {capacity_error_count} 次失败，进入深度休眠 {self.deep_sleep_duration/60:.1f} 分钟..."
                        log_msg(sleep_msg, "WARNING")
                        telegram_notify(sleep_msg, self.tg_config)
                        
                        # 睡眠循环，支持中途停止
                        sleep_steps = int(self.deep_sleep_duration)
                        for _ in range(sleep_steps):
                            if self.state.stop_event.is_set(): return
                            time.sleep(1)
                        
                        capacity_error_count = 0
                        log_msg("⏰ 休眠结束，继续尝试...", "INFO")
                        actual_wait = 0 # 醒来立即尝试
                
                else: # 其他错误
                    err_msg = str(e.message)
                    self.state.stats['last_status'] = f"Error: {e.status}"
                    if "Service limit" in err_msg and e.status == 400:
                        log_msg(f"❌ 配额不足: {err_msg}", "ERROR")
                        telegram_notify(f"❌ 配额不足，脚本停止: {err_msg}", self.tg_config)
                        self.state.running = False
                        break
                    else:
                        log_msg(f"❌ API 错误: {e.status} - {err_msg}", "ERROR")
            
            except Exception as e:
                log_msg(f"❌ 未知系统错误: {str(e)}", "ERROR")
                self.state.running = False
                break
            
            # 等待延时
            if actual_wait > 0:
                time.sleep(actual_wait)

# ==========================================
# Flask Web 应用
# ==========================================

app = Flask(__name__)
app.secret_key = SECRET_KEY

# HTML 模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oracle ARM Sniper</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Courier New', monospace; }
        .input-dark { background-color: #1e293b; border: 1px solid #334155; color: #fff; }
        .input-dark:focus { border-color: #3b82f6; outline: none; }
        .log-box { height: 300px; overflow-y: scroll; font-size: 0.85rem; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
    </style>
</head>
<body class="min-h-screen">

{% if not logged_in %}
<!-- 登录界面 -->
<div class="flex items-center justify-center h-screen">
    <div class="bg-slate-800 p-8 rounded-lg shadow-xl w-96 border border-slate-700">
        <h1 class="text-2xl font-bold mb-6 text-center text-green-500"><i class="fas fa-terminal mr-2"></i>ACCESS CONTROL</h1>
        <form method="POST" action="/login">
            <input type="password" name="password" placeholder="Enter Password" class="w-full p-3 rounded mb-4 input-dark">
            <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded transition">LOGIN</button>
        </form>
    </div>
</div>
{% else %}

<!-- 主控制台 -->
<nav class="bg-slate-900 border-b border-slate-700 p-4 sticky top-0 z-50">
    <div class="container mx-auto flex justify-between items-center">
        <div class="text-xl font-bold text-green-500"><i class="fas fa-robot mr-2"></i>Oracle ARM Sniper</div>
        <div>
            <span id="status-badge" class="px-3 py-1 rounded-full text-sm font-bold bg-gray-600 text-gray-200">IDLE</span>
            <a href="/logout" class="ml-4 text-red-400 hover:text-red-300"><i class="fas fa-sign-out-alt"></i></a>
        </div>
    </div>
</nav>

<div class="container mx-auto p-4 grid grid-cols-1 lg:grid-cols-3 gap-6">
    
    <!-- 左侧：配置面板 -->
    <div class="lg:col-span-1 space-y-6">
        <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
            <h2 class="text-lg font-bold mb-4 text-blue-400"><i class="fas fa-id-card mr-2"></i>OCI Credentials</h2>
            <form id="config-form" class="space-y-3">
                <div>
                    <label class="text-xs text-slate-400">User OCID</label>
                    <input type="text" name="user" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.user }}">
                </div>
                <div>
                    <label class="text-xs text-slate-400">Tenancy OCID</label>
                    <input type="text" name="tenancy" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.tenancy }}">
                </div>
                <div>
                    <label class="text-xs text-slate-400">Region</label>
                    <input type="text" name="region" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.region }}">
                </div>
                <div>
                    <label class="text-xs text-slate-400">Fingerprint</label>
                    <input type="text" name="fingerprint" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.fingerprint }}">
                </div>
                <div>
                    <label class="text-xs text-slate-400">Private Key (Paste Content)</label>
                    <textarea name="key_content" rows="4" class="w-full p-2 rounded input-dark text-xs font-mono">{{ config.oci.key_content }}</textarea>
                </div>
            </form>
        </div>

        <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
            <h2 class="text-lg font-bold mb-4 text-purple-400"><i class="fas fa-server mr-2"></i>Instance Config</h2>
            <form id="instance-form" class="space-y-3">
                <div>
                    <label class="text-xs text-slate-400">Availability Domain (e.g., Uocm:AP-SEOUL-1-AD-1)</label>
                    <input type="text" name="availability_domain" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.availability_domain }}">
                </div>
                <div>
                    <label class="text-xs text-slate-400">Subnet ID</label>
                    <input type="text" name="subnet_id" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.subnet_id }}">
                </div>
                <div>
                    <label class="text-xs text-slate-400">Image ID</label>
                    <input type="text" name="image_id" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.image_id }}">
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="text-xs text-slate-400">OCPUs</label>
                        <input type="number" name="ocpus" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.ocpus }}">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400">RAM (GB)</label>
                        <input type="number" name="memory_in_gbs" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.memory_in_gbs }}">
                    </div>
                </div>
                 <div>
                    <label class="text-xs text-slate-400">SSH Public Key</label>
                    <textarea name="ssh_key" rows="2" class="w-full p-2 rounded input-dark text-xs font-mono">{{ config.instance.ssh_key }}</textarea>
                </div>
            </form>
        </div>

         <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
            <h2 class="text-lg font-bold mb-4 text-blue-300"><i class="fab fa-telegram mr-2"></i>Telegram Bot</h2>
            <form id="tg-form" class="space-y-3">
                <div class="flex items-center mb-2">
                    <input type="checkbox" name="tg_enabled" id="tg_enabled" {% if config.telegram.enabled %}checked{% endif %} class="mr-2">
                    <label for="tg_enabled" class="text-sm">Enable Notification</label>
                </div>
                <div>
                    <input type="text" name="tg_token" placeholder="Bot Token" class="w-full p-2 rounded input-dark text-sm" value="{{ config.telegram.token }}">
                </div>
                <div>
                    <input type="text" name="tg_chat_id" placeholder="Chat ID" class="w-full p-2 rounded input-dark text-sm" value="{{ config.telegram.chat_id }}">
                </div>
            </form>
            <button onclick="saveConfig()" class="w-full mt-4 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition">Save All Config</button>
        </div>
    </div>

    <!-- 右侧：运行监控 -->
    <div class="lg:col-span-2 space-y-6">
        <!-- 状态卡片 -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 text-center">
                <div class="text-slate-400 text-xs uppercase">Attempts</div>
                <div class="text-2xl font-bold text-white" id="stat-attempts">0</div>
            </div>
            <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 text-center">
                <div class="text-slate-400 text-xs uppercase">Last Status</div>
                <div class="text-lg font-bold text-yellow-500 truncate" id="stat-status">None</div>
            </div>
            <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 text-center">
                <div class="text-slate-400 text-xs uppercase">Delay</div>
                <div class="text-xl font-bold text-blue-400" id="stat-delay">0s</div>
            </div>
             <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 text-center">
                <div class="text-slate-400 text-xs uppercase">Start Time</div>
                <div class="text-sm font-bold text-gray-300 mt-1" id="stat-start">--</div>
            </div>
        </div>

        <!-- 成功卡片 (隐藏) -->
        <div id="success-card" class="hidden bg-green-900/50 border border-green-500 p-6 rounded-lg text-center animate-pulse">
            <h2 class="text-3xl font-bold text-green-400 mb-2">🎉 SUCCESS!</h2>
            <p class="text-xl text-white">Public IP: <span id="success-ip" class="font-mono bg-black px-2 py-1 rounded"></span></p>
            <p class="text-sm text-green-300 mt-2">Check logs for root password.</p>
        </div>

        <!-- 日志窗口 -->
        <div class="bg-slate-900 rounded-lg border border-slate-700 shadow-inner">
            <div class="bg-slate-800 px-4 py-2 border-b border-slate-700 flex justify-between items-center">
                <span class="text-xs font-mono text-slate-400">System Logs</span>
                <button onclick="clearLogs()" class="text-xs text-slate-500 hover:text-white"><i class="fas fa-trash"></i> Clear</button>
            </div>
            <div id="log-container" class="log-box p-4 font-mono text-xs space-y-1">
                <div class="text-slate-500">Waiting for commands...</div>
            </div>
        </div>

        <!-- 控制按钮 -->
        <div class="grid grid-cols-2 gap-4">
            <button onclick="startSniper()" id="btn-start" class="bg-green-600 hover:bg-green-700 text-white font-bold py-4 rounded text-lg transition shadow-lg shadow-green-900/50">
                <i class="fas fa-play mr-2"></i> START SNIPER
            </button>
            <button onclick="stopSniper()" id="btn-stop" class="bg-red-600 hover:bg-red-700 text-white font-bold py-4 rounded text-lg transition opacity-50 cursor-not-allowed" disabled>
                <i class="fas fa-stop mr-2"></i> STOP
            </button>
        </div>
    </div>
</div>

<script>
    let isRunning = false;

    // 保存配置
    function saveConfig() {
        const ociData = new FormData(document.getElementById('config-form'));
        const insData = new FormData(document.getElementById('instance-form'));
        const tgData = new FormData(document.getElementById('tg-form'));
        
        const config = {
            oci: Object.fromEntries(ociData),
            instance: Object.fromEntries(insData),
            telegram: {
                enabled: document.getElementById('tg_enabled').checked,
                token: tgData.get('tg_token'),
                chat_id: tgData.get('tg_chat_id')
            }
        };

        fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        })
        .then(r => r.json())
        .then(data => {
            alert(data.msg);
        });
    }

    // 启动
    function startSniper() {
        fetch('/api/start', {method: 'POST'})
        .then(r => r.json())
        .then(data => {
            if(data.status === 'error') {
                alert(data.msg);
            } else {
                updateUIState(true);
            }
        });
    }

    // 停止
    function stopSniper() {
        fetch('/api/stop', {method: 'POST'})
        .then(r => r.json())
        .then(() => updateUIState(false));
    }

    // UI状态切换
    function updateUIState(running) {
        isRunning = running;
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const badge = document.getElementById('status-badge');

        if(running) {
            btnStart.disabled = true;
            btnStart.classList.add('opacity-50', 'cursor-not-allowed');
            btnStop.disabled = false;
            btnStop.classList.remove('opacity-50', 'cursor-not-allowed');
            badge.innerText = "RUNNING";
            badge.className = "px-3 py-1 rounded-full text-sm font-bold bg-green-600 text-white animate-pulse";
        } else {
            btnStart.disabled = false;
            btnStart.classList.remove('opacity-50', 'cursor-not-allowed');
            btnStop.disabled = true;
            btnStop.classList.add('opacity-50', 'cursor-not-allowed');
            badge.innerText = "STOPPED";
            badge.className = "px-3 py-1 rounded-full text-sm font-bold bg-red-600 text-white";
        }
    }

    // 轮询日志和状态
    setInterval(() => {
        fetch('/api/status')
        .then(r => r.json())
        .then(data => {
            // 更新统计
            document.getElementById('stat-attempts').innerText = data.stats.attempts;
            document.getElementById('stat-status').innerText = data.stats.last_status;
            document.getElementById('stat-delay').innerText = data.stats.current_delay;
            document.getElementById('stat-start').innerText = data.stats.start_time || '--';
            
            if (data.running !== isRunning) {
                updateUIState(data.running);
            }

            if (data.stats.success) {
                document.getElementById('success-card').classList.remove('hidden');
                document.getElementById('success-ip').innerText = data.stats.public_ip;
            }

            // 更新日志
            const logContainer = document.getElementById('log-container');
            if (data.logs.length > 0) {
                data.logs.forEach(log => {
                    const color = log.level === 'ERROR' ? 'text-red-500' : (log.level === 'SUCCESS' ? 'text-green-400' : (log.level === 'WARNING' ? 'text-yellow-400' : 'text-slate-300'));
                    const div = document.createElement('div');
                    div.className = `${color}`;
                    div.innerHTML = `<span class="opacity-50">[${log.time}]</span> ${log.message}`;
                    logContainer.appendChild(div);
                });
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        });
    }, 2000);

    function clearLogs() {
        document.getElementById('log-container').innerHTML = '';
    }
</script>
{% endif %}
</body>
</html>
"""

# ==========================================
# Flask 路由
# ==========================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET'])
def index():
    if not session.get('logged_in'):
        return render_template_string(HTML_TEMPLATE, logged_in=False)
    return render_template_string(HTML_TEMPLATE, logged_in=True, config=sniper_state.config)

@app.route('/login', methods=['POST'])
def login():
    if request.form['password'] == WEB_PASSWORD:
        session['logged_in'] = True
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/api/config', methods=['POST'])
@login_required
def save_config():
    data = request.json
    sniper_state.config = data
    log_msg("配置已更新", "INFO")
    return jsonify({"status": "ok", "msg": "Config Saved"})

@app.route('/api/start', methods=['POST'])
@login_required
def start_sniper():
    if sniper_state.running:
        return jsonify({"status": "error", "msg": "Already running"})
    
    # 检查必要配置
    if not sniper_state.config['oci']['user'] or not sniper_state.config['oci']['key_content']:
         return jsonify({"status": "error", "msg": "Missing OCI Config (User or Key)"})

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
        log_msg("停止指令已发送...", "WARNING")
        # 稍微给一点时间让线程退出
        time.sleep(1)
        if not sniper_state.thread.is_alive():
             sniper_state.running = False
    return jsonify({"status": "ok"})

@app.route('/api/status')
@login_required
def get_status():
    logs = []
    try:
        while True:
            logs.append(log_queue.get_nowait())
    except queue.Empty:
        pass
        
    return jsonify({
        "running": sniper_state.running,
        "stats": sniper_state.stats,
        "logs": logs
    })

# ==========================================
# 入口
# ==========================================
if __name__ == '__main__':
    # 屏蔽 Flask 默认日志，避免刷屏
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    print(f"[*] Panel started at http://0.0.0.0:{WEB_PORT}")
    print(f"[*] Password: {WEB_PASSWORD}")
    
    app.run(host='0.0.0.0', port=WEB_PORT, debug=False)

# -*- coding: utf-8 -*-
"""
Oracle Cloud ARM Sniper with Web Panel (TF Upload Supported)
集成 Web 面板、main.tf 自动解析、日志监控、退避算法与深度休眠功能的甲骨文抢机脚本。

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
import re
from datetime import datetime
from functools import wraps

# Flask & OCI Imports
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
import oci
from oci.core import ComputeClient, VirtualNetworkClient

# ==========================================
# 全局配置
# ==========================================
WEB_PORT = 5000
WEB_PASSWORD = "admin"  # 面板登录密码
SECRET_KEY = os.urandom(24) 

# ==========================================
# 抢机策略配置
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
log_queue = queue.Queue(maxsize=1000)

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
        self.config = {
            "oci": {
                "user": "",
                "fingerprint": "",
                "tenancy": "",
                "region": "",
                "key_content": ""
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
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] [{level}] {msg}"
    print(formatted_msg)
    try:
        log_queue.put({"time": timestamp, "level": level, "message": msg}, block=False)
    except queue.Full:
        pass

def telegram_notify(message, config):
    if not config['enabled'] or not config['token'] or not config['chat_id']:
        return
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
        # 提取关键字段
        patterns = {
            'availability_domain': r'availability_domain\s*=\s*"(.*)"',
            'subnet_id': r'subnet_id\s*=\s*"(.*)"',
            'source_id': r'source_id\s*=\s*"(.*)"', # image_id
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
                # 特殊处理
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
        self.tg_config = state.config['telegram']
        
        self.base_delay = DEFAULT_STRATEGY['base_delay']
        self.max_delay = DEFAULT_STRATEGY['max_delay']
        self.backoff_factor = DEFAULT_STRATEGY['backoff_factor']
        self.deep_sleep_threshold = DEFAULT_STRATEGY['deep_sleep_threshold']
        self.deep_sleep_duration = DEFAULT_STRATEGY['deep_sleep_duration']

        try:
            config_dict = {
                "user": self.oci_config['user'],
                "fingerprint": self.oci_config['fingerprint'],
                "tenancy": self.oci_config['tenancy'],
                "region": self.oci_config['region'],
                "key_content": self.oci_config['key_content']
            }
            # 简单校验
            for k, v in config_dict.items():
                if not v: raise ValueError(f"缺少 OCI 配置项: {k}")

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
        log_msg("🚀 抢机任务已启动...", "INFO")
        telegram_notify(f"脚本已启动\n目标: {self.ins_config['display_name']}\n配置: {self.ins_config['ocpus']}C / {self.ins_config['memory_in_gbs']}G", self.tg_config)
        
        user_data, root_pwd = self.generate_userdata()
        current_delay = self.base_delay
        backoff_attempt = 0
        capacity_error_count = 0
        self.state.stats['start_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        while not self.state.stop_event.is_set():
            jitter = random.uniform(2, 5)
            actual_wait = current_delay + jitter
            self.state.stats['current_delay'] = f"{actual_wait:.2f}s"
            
            try:
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
                        hostname_label=self.ins_config['display_name'].lower().replace(" ", "-")
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
                
                instance = response.data
                self.state.stats['success'] = True
                self.state.stats['last_status'] = "SUCCESS"
                self.state.stats['attempts'] += 1
                
                log_msg(f"🎉 抢注成功! Instance ID: {instance.id}", "SUCCESS")
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
                if e.status == 429:
                    backoff_attempt += 1
                    calculated_delay = self.base_delay * (self.backoff_factor ** backoff_attempt)
                    current_delay = min(calculated_delay, self.max_delay)
                    self.state.stats['last_status'] = "429 Too Many Requests"
                    log_msg(f"⚠️ 请求限速 (429). 退避重试: {backoff_attempt}", "WARNING")
                
                elif e.status == 500 and 'Out of host capacity' in str(e.message):
                    capacity_error_count += 1
                    backoff_attempt = 0
                    current_delay = self.base_delay
                    self.state.stats['last_status'] = "Out of Capacity"
                    if capacity_error_count % 10 == 0:
                        log_msg(f"⏳ 容量不足 (500). 连续次数: {capacity_error_count}", "INFO")

                    if capacity_error_count >= self.deep_sleep_threshold:
                        sleep_msg = f"😴 触发深度休眠 ({self.deep_sleep_duration/60:.1f} min)..."
                        log_msg(sleep_msg, "WARNING")
                        telegram_notify(sleep_msg, self.tg_config)
                        for _ in range(int(self.deep_sleep_duration)):
                            if self.state.stop_event.is_set(): return
                            time.sleep(1)
                        capacity_error_count = 0
                        actual_wait = 0
                else:
                    err_msg = str(e.message)
                    self.state.stats['last_status'] = f"Error: {e.status}"
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

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oracle ARM Sniper Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
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
<div class="flex items-center justify-center h-screen">
    <div class="bg-slate-800 p-8 rounded-lg shadow-xl w-96 border border-slate-700">
        <h1 class="text-2xl font-bold mb-6 text-center text-green-500"><i class="fas fa-shield-alt mr-2"></i>SNIPER LOGIN</h1>
        <form method="POST" action="/login">
            <input type="password" name="password" placeholder="Password" class="w-full p-3 rounded mb-4 input-dark">
            <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded transition">ENTER SYSTEM</button>
        </form>
    </div>
</div>
{% else %}

<nav class="bg-slate-900 border-b border-slate-700 p-4 sticky top-0 z-50">
    <div class="container mx-auto flex justify-between items-center">
        <div class="text-xl font-bold text-green-500"><i class="fas fa-crosshairs mr-2"></i>Oracle ARM Sniper <span class="text-xs text-slate-500 ml-2">PRO</span></div>
        <div>
            <span id="status-badge" class="px-3 py-1 rounded-full text-sm font-bold bg-gray-600 text-gray-200">IDLE</span>
            <a href="/logout" class="ml-4 text-red-400 hover:text-red-300"><i class="fas fa-power-off"></i></a>
        </div>
    </div>
</nav>

<div class="container mx-auto p-4 grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Config Column -->
    <div class="lg:col-span-1 space-y-6">
        
        <!-- OCI Config -->
        <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
            <h2 class="text-lg font-bold mb-4 text-blue-400"><i class="fas fa-key mr-2"></i>OCI Credentials</h2>
            <form id="config-form" class="space-y-3">
                <div><label class="text-xs text-slate-400">User OCID</label><input type="text" name="user" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.user }}"></div>
                <div><label class="text-xs text-slate-400">Tenancy OCID</label><input type="text" name="tenancy" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.tenancy }}"></div>
                <div><label class="text-xs text-slate-400">Region</label><input type="text" name="region" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.region }}"></div>
                <div><label class="text-xs text-slate-400">Fingerprint</label><input type="text" name="fingerprint" class="w-full p-2 rounded input-dark text-sm" value="{{ config.oci.fingerprint }}"></div>
                <div><label class="text-xs text-slate-400">Private Key (Content)</label><textarea name="key_content" rows="3" class="w-full p-2 rounded input-dark text-xs font-mono">{{ config.oci.key_content }}</textarea></div>
            </form>
        </div>

        <!-- Instance Config -->
        <div class="bg-slate-800 p-5 rounded-lg border border-slate-700 relative">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-lg font-bold text-purple-400"><i class="fas fa-server mr-2"></i>Instance Config</h2>
                
                <!-- Upload Button -->
                <div class="relative">
                    <input type="file" id="tf-upload" class="hidden" onchange="uploadTfFile()">
                    <label for="tf-upload" class="cursor-pointer bg-purple-600 hover:bg-purple-700 text-white text-xs px-3 py-1 rounded transition">
                        <i class="fas fa-file-upload mr-1"></i> Upload main.tf
                    </label>
                </div>
            </div>

            <form id="instance-form" class="space-y-3">
                <div><label class="text-xs text-slate-400">Availability Domain</label><input type="text" id="inp_ad" name="availability_domain" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.availability_domain }}"></div>
                <div><label class="text-xs text-slate-400">Subnet ID</label><input type="text" id="inp_subnet" name="subnet_id" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.subnet_id }}"></div>
                <div><label class="text-xs text-slate-400">Image ID</label><input type="text" id="inp_image" name="image_id" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.image_id }}"></div>
                <div class="grid grid-cols-3 gap-2">
                    <div><label class="text-xs text-slate-400">OCPUs</label><input type="number" id="inp_cpu" name="ocpus" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.ocpus }}"></div>
                    <div><label class="text-xs text-slate-400">RAM (GB)</label><input type="number" id="inp_ram" name="memory_in_gbs" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.memory_in_gbs }}"></div>
                    <div><label class="text-xs text-slate-400">Disk (GB)</label><input type="number" id="inp_disk" name="disk_size" class="w-full p-2 rounded input-dark text-sm" value="{{ config.instance.disk_size }}"></div>
                </div>
                <div><label class="text-xs text-slate-400">SSH Public Key</label><textarea id="inp_ssh" name="ssh_key" rows="2" class="w-full p-2 rounded input-dark text-xs font-mono">{{ config.instance.ssh_key }}</textarea></div>
            </form>
        </div>

        <!-- Telegram -->
        <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
            <h2 class="text-lg font-bold mb-4 text-blue-300"><i class="fab fa-telegram mr-2"></i>Notify</h2>
            <form id="tg-form" class="space-y-3">
                <div class="flex items-center mb-2">
                    <input type="checkbox" name="tg_enabled" id="tg_enabled" {% if config.telegram.enabled %}checked{% endif %} class="mr-2">
                    <label for="tg_enabled" class="text-sm">Enabled</label>
                </div>
                <div><input type="text" name="tg_token" placeholder="Bot Token" class="w-full p-2 rounded input-dark text-sm" value="{{ config.telegram.token }}"></div>
                <div><input type="text" name="tg_chat_id" placeholder="Chat ID" class="w-full p-2 rounded input-dark text-sm" value="{{ config.telegram.chat_id }}"></div>
            </form>
            <button onclick="saveConfig()" class="w-full mt-4 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition">SAVE CONFIGURATION</button>
        </div>
    </div>

    <!-- Monitor Column -->
    <div class="lg:col-span-2 space-y-6">
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
                <div class="text-slate-400 text-xs uppercase">Wait</div>
                <div class="text-xl font-bold text-blue-400" id="stat-delay">0s</div>
            </div>
             <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 text-center">
                <div class="text-slate-400 text-xs uppercase">Started</div>
                <div class="text-sm font-bold text-gray-300 mt-1" id="stat-start">--</div>
            </div>
        </div>

        <div id="success-card" class="hidden bg-green-900/50 border border-green-500 p-6 rounded-lg text-center animate-pulse">
            <h2 class="text-3xl font-bold text-green-400 mb-2">🎉 SUCCESS!</h2>
            <p class="text-xl text-white">Public IP: <span id="success-ip" class="font-mono bg-black px-2 py-1 rounded"></span></p>
        </div>

        <div class="bg-slate-900 rounded-lg border border-slate-700 shadow-inner">
            <div class="bg-slate-800 px-4 py-2 border-b border-slate-700 flex justify-between items-center">
                <span class="text-xs font-mono text-slate-400">Live Logs</span>
                <button onclick="clearLogs()" class="text-xs text-slate-500 hover:text-white"><i class="fas fa-trash"></i></button>
            </div>
            <div id="log-container" class="log-box p-4 font-mono text-xs space-y-1">
                <div class="text-slate-500">System Ready.</div>
            </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
            <button onclick="startSniper()" id="btn-start" class="bg-green-600 hover:bg-green-700 text-white font-bold py-4 rounded text-lg transition shadow-lg shadow-green-900/50"><i class="fas fa-play mr-2"></i> START</button>
            <button onclick="stopSniper()" id="btn-stop" class="bg-red-600 hover:bg-red-700 text-white font-bold py-4 rounded text-lg transition opacity-50 cursor-not-allowed" disabled><i class="fas fa-stop mr-2"></i> STOP</button>
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

        fetch('/api/upload_tf', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if(data.status === 'ok') {
                const d = data.data;
                if(d.availability_domain) document.getElementById('inp_ad').value = d.availability_domain;
                if(d.subnet_id) document.getElementById('inp_subnet').value = d.subnet_id;
                if(d.image_id) document.getElementById('inp_image').value = d.image_id;
                if(d.ocpus) document.getElementById('inp_cpu').value = d.ocpus;
                if(d.memory_in_gbs) document.getElementById('inp_ram').value = d.memory_in_gbs;
                if(d.disk_size) document.getElementById('inp_disk').value = d.disk_size;
                if(d.ssh_key) document.getElementById('inp_ssh').value = d.ssh_key;
                alert("main.tf 解析成功！表单已自动填充，请检查后保存。");
            } else {
                alert("解析失败: " + data.msg);
            }
        });
    }

    function saveConfig() {
        const config = {
            oci: Object.fromEntries(new FormData(document.getElementById('config-form'))),
            instance: Object.fromEntries(new FormData(document.getElementById('instance-form'))),
            telegram: {
                enabled: document.getElementById('tg_enabled').checked,
                token: document.querySelector('[name=tg_token]').value,
                chat_id: document.querySelector('[name=tg_chat_id]').value
            }
        };
        fetch('/api/config', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config)})
        .then(r => r.json()).then(d => alert(d.msg));
    }

    function startSniper() {
        fetch('/api/start', {method: 'POST'}).then(r => r.json()).then(d => {
            if(d.status === 'error') alert(d.msg);
            else updateUIState(true);
        });
    }

    function stopSniper() {
        fetch('/api/stop', {method: 'POST'}).then(() => updateUIState(false));
    }

    function updateUIState(running) {
        isRunning = running;
        document.getElementById('btn-start').disabled = running;
        document.getElementById('btn-start').classList.toggle('opacity-50', running);
        document.getElementById('btn-stop').disabled = !running;
        document.getElementById('btn-stop').classList.toggle('opacity-50', !running);
        document.getElementById('status-badge').innerText = running ? "RUNNING" : "STOPPED";
        document.getElementById('status-badge').className = running ? "px-3 py-1 rounded-full text-sm font-bold bg-green-600 text-white animate-pulse" : "px-3 py-1 rounded-full text-sm font-bold bg-red-600 text-white";
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
                    const color = log.level === 'ERROR' ? 'text-red-500' : (log.level === 'SUCCESS' ? 'text-green-400' : (log.level === 'WARNING' ? 'text-yellow-400' : 'text-slate-300'));
                    const div = document.createElement('div');
                    div.className = color;
                    div.innerHTML = `<span class="opacity-50">[${log.time}]</span> ${log.message}`;
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
def save_config():
    sniper_state.config = request.json
    log_msg("配置已保存", "INFO")
    return jsonify({"status": "ok", "msg": "Config Saved"})

@app.route('/api/start', methods=['POST'])
@login_required
def start_sniper():
    if sniper_state.running: return jsonify({"status": "error", "msg": "Running"})
    if not sniper_state.config['oci']['user'] or not sniper_state.config['oci']['key_content']:
         return jsonify({"status": "error", "msg": "Missing Credentials"})
    
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
        log_msg("正在停止...", "WARNING")
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
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print(f"[*] Panel: http://0.0.0.0:{WEB_PORT}")
    print(f"[*] Password: {WEB_PASSWORD}")
    app.run(host='0.0.0.0', port=WEB_PORT, debug=False)

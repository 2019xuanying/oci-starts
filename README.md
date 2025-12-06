# **🐢 Oracle Cloud ARM Sniper Web Panel**

这是一个基于 Python Flask 的 Oracle Cloud (甲骨文云) 自动抢机脚本，集成了现代化的 Web 控制面板。它旨在帮助用户自动申请 Oracle Cloud 紧俏的 ARM 实例（如首尔、东京等区域）。

与传统命令行脚本不同，本项目拥有**图形化界面**，支持**在线配置参数**、**实时日志监控**、**Telegram 通知**以及智能的**防封/退避算法**。

## **✨ 主要功能**

* **🖥️ Web 控制面板**：无需修改代码或配置文件，直接在浏览器中管理所有操作。  
* **🔑 安全登录**：内置密码验证，防止未经授权的访问（默认密码可修改）。  
* **📋 在线配置**：支持直接粘贴 API 私钥（Private Key）内容，无需上传密钥文件，更加安全便捷。  
* **🛡️ 智能防封 (Anti-Ban)**：  
  * **指数退避 (Backoff)**：遇到 429 (Too Many Requests) 错误时，自动延长重试间隔。  
  * **深度休眠 (Deep Sleep)**：连续遭遇容量不足 (Out of Host Capacity) 时，自动休眠一段时间，避免无效请求导致封号。  
* **📊 实时监控**：面板实时展示尝试次数、当前延迟、最近一次 API 状态和详细日志。  
* **📱 Telegram 通知**：启动、成功抢注或遇到严重错误时发送即时通知。  
* **🚀 自动开机配置**：抢注成功后，脚本会自动配置实例的 Root 密码并开启 SSH 登录。

## **🛠️ 安装依赖**

请确保你的系统已安装 Python 3.6+。

在终端执行以下命令安装所需库：

pip install flask oci requests

## **🚀 快速开始**

1. 启动脚本  
   下载 oracle\_sniper\_web.py 到本地，在终端运行：  
   python oracle\_sniper\_web.py

   *默认运行在 5000 端口。如果需要修改端口或默认密码（默认为 admin），请编辑脚本文件头部的全局配置区域。*  
2. 访问面板  
   打开浏览器访问：http://localhost:5000 (如果是服务器部署，请使用服务器 IP)。  
3. 登录  
   输入密码（默认：admin）进入控制台。  
4. **填写配置**  
   * **OCI Credentials**: 填入甲骨文 API 的 User OCID, Tenancy OCID, Region, Fingerprint。直接将 .pem 私钥的内容复制粘贴到 "Private Key" 框中。  
   * **Instance Config**: 填入目标机器的参数（可用区 AD, 子网 ID, 镜像 ID, SSH 公钥等）。  
   * **Telegram Bot** (可选): 填入 Bot Token 和 Chat ID 以启用通知。  
5. 启动抢机  
   点击 START SNIPER 按钮，观察右侧日志窗口。

## **⚙️ 参数获取指南**

### **1\. 甲骨文 API 信息 (OCI Credentials)**

登录 Oracle Cloud 控制台：

* 点击右上角头像 \-\> **My Profile** \-\> **API Keys** \-\> **Add API Key**。  
* 下载私钥 (.pem 文件)，用记事本打开复制内容。  
* 页面会显示 User OCID, Fingerprint, Tenancy OCID, Region 等信息。

### **2\. 实例配置 (Instance Config)**

推荐方法：

1. 在甲骨文后台手动尝试创建一个实例（选择 ARM 4核 24G）。  
2. 在浏览器按 F12 打开开发者工具，点击“创建”按钮。  
3. 在 Network (网络) 选项卡中找到 instances 请求，查看 Payload/请求体，即可获取 image\_id, subnet\_id, availability\_domain 等精确参数。

## **⚠️ 免责声明**

* 本工具仅供学习和研究使用。  
* 作者不对使用本脚本造成的任何后果（包括但不限于账号被封禁、资源滥用等）负责。  
* 请合理设置抢注频率，避免对 Oracle 服务造成过大压力。

*Happy Sniping\!* 🎯
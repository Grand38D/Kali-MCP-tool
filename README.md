# MCP-Kali-Server 安装与配置指南

MCP-Kali-Server 是一个轻量级 API 桥接器，用于连接 MCP 客户端（如 Claude Desktop、chatbox）到 Kali Linux 终端，实现 AI 辅助渗透测试、CTF 挑战解决和自动化安全测试。

## 目录

- [系统要求](#系统要求)
- [安装步骤](#安装步骤)
  - [服务器端安装](#服务器端安装)
  - [客户端配置](#客户端配置)
- [环境变量配置](#环境变量配置)
- [启动服务](#启动服务)
- [API 端点说明](#api-端点说明)
- [常见问题排查](#常见问题排查)
- [高级配置](#高级配置)
- [安全注意事项](#安全注意事项)

## 系统要求

### 服务器端（Kali Linux）
- Kali Linux（推荐最新版本）
- Python 3.8+
- 网络连接

### 客户端
- Windows/Linux/macOS
- Python 3.8+
- MCP 客户端（Claude Desktop 或 chatbox）

## 安装步骤

### 服务器端安装

1. **克隆仓库**

```bash
git clone https://github.com/Grand38D/MCP-Kali-Server.git
cd MCP-Kali-Server
```

2. **安装依赖**

对于标准版本：
```bash
pip3 install flask requests
```

对于 FastAPI 版本（推荐，性能更好）：
```bash
pip3 install fastapi uvicorn pydantic
```

3. **验证安装**

确保以下工具已安装在您的 Kali Linux 系统上：
```bash
which nmap gobuster sqlmap curl wget ffuf dirb nikto
```

如果缺少任何工具，请使用 apt 安装：
```bash
sudo apt update
sudo apt install -y nmap gobuster sqlmap curl wget ffuf dirb nikto
```

### 客户端配置

#### 通用配置

在客户端机器上，您需要配置 MCP 客户端连接到 Kali 服务器：

```bash
# 克隆仓库（如果尚未克隆）
git clone https://github.com/Grand38D/MCP-Kali-Server.git
cd MCP-Kali-Server
```

#### Claude Desktop 配置

编辑 Claude Desktop 配置文件：
- Windows: `C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

添加以下配置：

```json
{
    "mcpServers": {
        "kali_mcp": {
            "command": "python3",
            "args": [
                "/absolute/path/to/mcp_server.py",
                "--server",
                "http://KALI_IP:5000/"
            ]
        }
    }
}
```

将 `KALI_IP` 替换为您的 Kali Linux 服务器 IP 地址。

#### Chatbox 配置

在 Chat 桌面应用程序中：
1. 打开设置
2. 添加新的 MCP 配置
3. 输入命令：`python3 /absolute/path/to/mcp_server.py http://KALI_IP:5000`
4. 保存配置

## 环境变量配置

您可以通过环境变量自定义服务器行为：

| 环境变量 | 描述 | 默认值 |
|----------|------|--------|
| API_PORT | API 服务器端口 | 5000 |
| DEBUG_MODE | 调试模式 | 0 (关闭) |
| API_TOKEN | API 认证令牌 | 空 (不需要认证) |
| COMMAND_TIMEOUT | 命令执行超时时间（秒） | 180 |
| MAX_OUTPUT_CHARS | 最大输出字符数 | 50000 |
| MAX_CONCURRENCY | 最大并发执行命令数 | 3 |
| REAL_TIME_OUTPUT | 是否在服务器端实时显示命令执行结果 | 1 (启用) |
| ENABLE_CACHE | 是否启用命令结果缓存（仅 FastAPI 版本） | 1 (启用) |
| CACHE_SIZE | 缓存大小（条目数，仅 FastAPI 版本） | 100 |

设置环境变量示例：

```bash
export API_PORT=5000
export API_TOKEN="your_secure_token_here"
export COMMAND_TIMEOUT=300
```

## 启动服务



### FastAPI 版本

```bash
python3 kali_server_fastapi.py
```

或指定端口和调试模式：

```bash
python3 kali_server_fastapi.py --port 5000 --debug
```

禁用终端窗口：

```bash
python3 kali_server_fastapi.py --no-terminal
```

## API 端点说明

服务器提供以下主要 API 端点：

### 基础端点

- **GET /health**: 检查服务器健康状态
- **POST /api/command**: 执行通用命令
- **POST /api/command/stream**: 流式执行命令（仅 FastAPI 版本）

### 工具特定端点

- **POST /api/tools/nmap**: 执行 Nmap 扫描
- **POST /api/tools/gobuster**: 执行目录扫描
- **POST /api/tools/sqlmap**: 执行 SQL 注入测试
- **POST /api/tools/curl**: 执行 curl 请求
- **POST /api/tools/wget**: 下载文件
- **POST /api/tools/ffuf**: 执行模糊测试
- **POST /api/tools/dirb**: 执行目录暴力破解
- **POST /api/tools/nikto**: 执行 Web 服务器扫描

## 常见问题排查

### 连接问题

如果客户端无法连接到服务器：

1. 确认服务器 IP 地址和端口配置正确
2. 检查防火墙设置，确保端口已开放
3. 验证服务器是否正在运行：`ps aux | grep kali_server`
4. 检查服务器日志输出

### 命令执行问题

如果命令执行失败：

1. 检查工具是否已安装：`which <tool_name>`
2. 验证命令语法是否正确
3. 检查权限问题，某些命令可能需要 sudo 权限
4. 查看服务器日志获取详细错误信息

### 性能问题

如果遇到性能问题：

1. 增加 `MAX_CONCURRENCY` 值以允许更多并发命令
2. 对于 FastAPI 版本，确保启用缓存机制
3. 考虑增加 `COMMAND_TIMEOUT` 值以允许长时间运行的命令完成

## 高级配置

### 安全增强

为增强安全性，建议：

1. 设置强 API 令牌：
```bash
export API_TOKEN="complex_random_string_here"
```

2. 限制 API 访问仅来自特定 IP：
   - 使用防火墙规则限制访问
   ```bash
   sudo ufw allow from trusted_ip_address to any port 5000
   ```

3. 使用 HTTPS：
   - 生成自签名证书或使用 Let's Encrypt
   - 配置 HTTPS 反向代理（如 Nginx）

### 自定义终端窗口

FastAPI 版本支持自定义终端窗口：

```bash
# 修改终端窗口标题
export TERMINAL_WINDOW_TITLE="自定义终端标题"

# 修改命令日志文件路径
export TERMINAL_COMMAND_FILE="/path/to/custom_log_file.log"
```

## 安全注意事项

使用本工具时请注意以下安全事项：

1. **仅在受控环境中使用**：不要在生产环境中部署此服务器
2. **限制网络访问**：确保服务器仅对受信任的客户端可见
3. **使用 API 令牌**：始终设置强 API 令牌进行身份验证
4. **定期更新**：保持系统和工具的最新状态
5. **监控活动**：定期检查日志文件以识别潜在的滥用
6. **命令过滤**：某些命令（如 gobuster 的 -p 参数）已被限制以防止滥用

---
"这里的部分代码受到 https://github.com/whit3rabbit0/project_astro 的启发，请务必查看他们的项目",
如有任何问题或建议，请提交 GitHub Issue 或贡献 Pull Request。

**免责声明**：本工具仅用于合法的安全测试和教育目的。使用本工具进行未授权的安全测试是违法的，可能导致法律后果。

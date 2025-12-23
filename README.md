# 远程OCR MCP Server

这是一个基于 Model Context Protocol (MCP) 的远程 OCR 服务，支持通过配置文件指定 OCR API 接口。

## 文件说明

- `mcp_server.py` - MCP服务器主程序，提供 `ocr_image` 工具
- `run.py` - 独立运行的 OCR 脚本，可用于测试
- `start_mcp_server.sh` - MCP 服务器启动脚本
- `remote_ocr.toml` - 配置文件示例
- `requirements.txt` - Python 依赖包列表

## 安装依赖

```bash
pip install -r requirements.txt
```

或者创建虚拟环境：

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

## 使用方法

### 1. 配置文件

首先创建或编辑配置文件 `remote_ocr.toml`，填入 OCR API 的相关信息：

```toml
# Remote OCR API 配置
perm_url = "https://example.com/api/perm/single"
start_url = "https://example.com/api/ocr/image/beta"
status_url = "https://example.com/api/ocr/image/beta/status"
auth_token = "your-auth-token"
auth_uuid = "your-auth-uuid"
auth_cookie = "your-auth-cookie"
origin = "https://example.com"
mode = "single"
timeout_secs = 30
poll_interval_ms = 3000
poll_max_attempts = 10
poll_initial_delay_ms = 500
accept_invalid_certs = false
```

### 2. 作为 MCP Server 使用

在 Claude Desktop 配置文件中添加：

```json
{
  "mcpServers": {
    "ocr-server": {
      "command": "bash",
      "args": ["/opt/mystorage/github/ocr/start_mcp_server.sh"]
    }
  }
}
```

或者直接使用 Python：

```json
{
  "mcpServers": {
    "ocr-server": {
      "command": "python",
      "args": [
        "/opt/mystorage/github/ocr/mcp_server.py",
        "-c",
        "/opt/mystorage/github/ocr/remote_ocr.toml"
      ]
    }
  }
}
```

### 3. 独立运行测试

```bash
python run.py --single-pic-path /path/to/image.png
```

## 认证配置

所有 API 接口信息都通过配置文件 `remote_ocr.toml` 指定，代码中不包含具体的 API 地址和认证信息。

### 配置参数说明

- `perm_url` - 获取权限 token 的 API 地址
- `start_url` - 启动 OCR 任务的 API 地址
- `status_url` - 查询 OCR 状态的 API 地址
- `auth_token` - API 认证 token
- `auth_uuid` - API 认证 UUID
- `auth_cookie` - API 认证 Cookie
- `origin` - API 来源域名
- `mode` - OCR 模式（如 "single"）
- `timeout_secs` - 请求超时时间（秒）
- `poll_interval_ms` - 轮询间隔（毫秒）
- `poll_max_attempts` - 最大轮询次数
- `poll_initial_delay_ms` - 首次轮询前的延迟（毫秒）
- `accept_invalid_certs` - 是否接受无效证书（true/false）

### 如何获取认证信息

如果使用可通过浏览器抓包获取：

1. 访问 OCR 服务网站
2. 打开浏览器开发者工具（F12）
3. 进行一次 OCR 操作
4. 在网络请求中找到相关的 token、uuid 和 cookie
5. 填入 `remote_ocr.toml` 配置文件

## 功能特性

- 支持多种图片格式（PNG、JPG、JPEG等）
- 通过配置文件指定 API 接口，代码与具体 API 解耦
- 异步处理，自动轮询获取结果
- 返回识别的文字、字数统计和置信度
- 完整的错误处理和日志记录
- 灵活的轮询配置（间隔、最大次数、初始延迟）

## 注意事项

- 配置文件中的认证信息需要有效
- 网络连接需要能访问配置的 API 地址
- **请勿在公共仓库中提交包含真实认证信息的配置文件**
- 建议将 `remote_ocr.toml` 添加到 `.gitignore` 中

#!/bin/bash
# MCP Server 启动脚本

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd $SCRIPT_DIR
# 激活虚拟环境（如果存在）
if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# 配置文件路径
CONFIG_FILE="${SCRIPT_DIR}/remote_ocr.toml"

# 启动 MCP Server
python "$SCRIPT_DIR/mcp_server.py" -c "$CONFIG_FILE"

# VulnAgent

VulnAgent 是一个面向**固件、二进制以及源码差异分析**的安全分析系统。后端基于 FastAPI，围绕“文件上传 → 参数收集 → 多智能体分析 → 结果落盘 / WebSocket 实时回传”组织能力。

当前主线能力包括：

- 固件/二进制差异分析
- 独立 Source Diff 源码差异安全分析
- Code Repair 源码修复辅助
- Hardcoded String Audit 硬编码字符串审计

运行产物默认保存在 `history/` 下，静态图片和 HTML diff 可通过 `/static/images/...` 访问。

---

## 1. 功能概览

### 1.1 固件 / 二进制差异分析

适用于两个版本的固件镜像、ELF、PE、动态库等输入。典型流程：

1. 上传文件到同一个 `chat_id`
2. 通过 `WS /v1/chat` 发起分析
3. 后端参数采集器收集 `cve_id` / `cwe_id` / `binary_filename` 等信息
4. 执行 Binwalk、IDA、BinDiff、LLM 分析
5. 将事件、结果、产物写入 `history/<chat_id>/`

### 1.2 Source Diff（独立源码分析流）

Source Diff 是**独立工具流**，不接入 `/v1/chat` 主分析流程。它有自己的文件上传接口和 WebSocket 分析入口。

支持上传源码文件后，对两个版本的源文件进行：

- HTML diff 生成
- hunk 级别差异抽取
- 基于 LLM 的安全相关性判定
- 安全变更摘要生成

默认工作目录：

- 输入目录：`history/source_diff_sessions/<chat_id>/`
- 输出目录：`history/source_diff_sessions/<chat_id>/source_diff/`

同时会复制一份 HTML diff 到 `images/temp_diffs/`，前端可直接访问 `/static/images/temp_diffs/...`。

### 1.3 Code Repair

对上传的源码文件进行修复建议与交互式修复流程。

### 1.4 Hardcoded String Audit

对单个二进制/固件文件提取硬编码字符串，并结合大模型识别账号口令、命令执行痕迹、SQL 语句、中间件版本等敏感信息。

---

## 2. 目录结构

```text
VulnAgent/
├── main.py                         # FastAPI 入口
├── client.py                       # 固件/二进制分析示例客户端
├── requirements.txt                # Python 依赖
├── alembic.ini                     # Alembic 配置
├── agent/
│   ├── VulnAgent.py                # 主分析流程
│   ├── source_diff_agent.py        # Source Diff 执行器
│   ├── source_diff_parameter_agent.py
│   ├── bindiff_agent.py
│   ├── binwalk.py
│   ├── ida_toolkits.py
│   └── IDAService/                 # Windows 侧 IDA 服务
├── config/
│   ├── config.ini
│   └── config.ini.example
├── db/
│   ├── models.py
│   ├── session.py
│   └── ...
├── migrations/
│   └── versions/
└── history/                        # 默认运行产物目录
```

---

## 3. 部署指南

## 3.1 环境要求

### Linux 主服务

建议环境：

- Ubuntu 20.04+ / Debian 系列
- Python 3.10+
- 可访问配置的大模型服务
- 可访问 Windows 侧 IDAService（如启用固件/二进制逆向流程）
- 如使用 PostgreSQL：需安装 `psycopg[binary]` 并执行 Alembic 迁移

### Windows IDAService（可远程）

建议环境：

- Windows
- IDA Pro 7.x
- BinDiff 插件
- 可被 Linux 主服务访问的 HTTP 服务

### 可选系统依赖

根据使用场景选择安装：

- `binwalk`：固件解包
- `bindiff`：BinExport 对比
- `xdotool`、`scrot`：Linux 图形界面下的 BinDiff UI 自动截图

---

## 3.2 创建 Python 环境

可以使用 Conda，也可以直接使用 venv。

### 方式一：Conda

```bash
conda create -n VulAgent python=3.10 -y
conda activate VulAgent
```

### 方式二：venv

```bash
python3.10 -m venv .venv
source .venv/bin/activate
```

---

## 3.3 安装依赖

```bash
cd VulnAgent
python -m pip install --upgrade pip
pip install -r requirements.txt
```

如果需要 PostgreSQL，`requirements.txt` 已包含 `psycopg[binary]`，无需单独安装。

---

## 3.4 安装系统工具（按需）

### Binwalk

```bash
sudo apt update
sudo apt install -y binwalk
```

### BinDiff CLI

请从官方渠道安装 Linux 版 BinDiff，并确保 `bindiff` 在 `PATH` 中。

```bash
bindiff --help
```

### GUI 截图依赖

```bash
sudo apt install -y xdotool scrot
```

---

## 3.5 配置文件

复制示例配置并修改：

```bash
cp config/config.ini.example config/config.ini
```

重点配置项：

### LLM 配置

在 `config/config.ini` 中选择一个可用模型小节并填写：

- `api_key`
- `base_url`
- `model_name`

例如：

```ini
[LLM.DeepSeek]
model_name = deepseek-chat
api_key = YOUR_DEEPSEEK_API_KEY
base_url = http://YOUR_DEEPSEEK_SERVER/v1
```

### 结果目录

```ini
[result.path]
savedir = history
```

### IDA 服务地址

```ini
[IDA_SERVICE]
service_url = http://<windows_host>:5000
```

### 数据库配置

```ini
[DATABASE]
url =
use_sqlite_fallback = true
```

数据库 URL 的解析优先级为：

1. 环境变量 `VULNAGENT_DATABASE_URL`
2. `config.ini` 中 `[DATABASE].url`
3. SQLite fallback（默认本地开发）

---

## 3.6 数据库初始化与迁移

VulnAgent 当前同时兼容：

- 本地开发：SQLite（默认）
- 正式部署：PostgreSQL（推荐）

### 本地开发（SQLite）

如果不配置数据库 URL，系统会默认使用：

```text
history/vulnagent.db
```

启动服务时会自动调用 `init_db()`，创建基础表，并补齐 SQLite 兼容列。

### PostgreSQL（推荐）

示例：

```bash
export VULNAGENT_DATABASE_URL='postgresql+psycopg://postgres:postgres@localhost:5432/vulnagent'
```

然后执行 Alembic 迁移：

```bash
alembic upgrade head
```

如果你希望完全依赖 PostgreSQL 而不回退到 SQLite，可在 `config.ini` 中设置：

```ini
[DATABASE]
use_sqlite_fallback = false
```

---

## 3.7 配置 Windows 侧 IDAService

请参考 `agent/IDAService/` 下的服务代码和说明，至少确保以下能力可用：

- 导出 BinExport / IDB
- 导出伪 C
- 截图导出（如启用）

主服务会通过 `config.ini` 中的 `[IDA_SERVICE].service_url` 调用远端接口。

典型要求：

1. 安装 IDA Pro 与 BinDiff 插件
2. 配置好导出脚本路径
3. 启动 Windows 侧 HTTP 服务
4. 确保 Linux 主服务可以访问该地址

---

## 3.8 启动服务

### 直接运行

```bash
python main.py
```

默认会监听：

- HTTP: `http://0.0.0.0:8001`
- WebSocket: `ws://0.0.0.0:8001`

### 使用 uvicorn

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

如果你希望与现有文档示例保持一致，也可以显式指定 `--port 8000`。
静态资源路径：

- `/static/images/...`

---

## 4. 使用指南

## 4.1 固件 / 二进制差异分析

### 第一步：上传文件

接口：`POST /v1/files`

表单字段：

- `file`: 上传文件
- `chat_id`: 会话标识
- `upload_role`: 可选，`old` 或 `new`

示例：

```bash
curl -X POST 'http://127.0.0.1:8000/v1/files' \
  -F 'chat_id=demo_001' \
  -F 'upload_role=old' \
  -F 'file=@/path/to/old.bin'

curl -X POST 'http://127.0.0.1:8000/v1/files' \
  -F 'chat_id=demo_001' \
  -F 'upload_role=new' \
  -F 'file=@/path/to/new.bin'
```

也可以使用仓库内的 [client.py](client.py)。

### 第二步：通过 WebSocket 发起分析

接口：`WS /v1/chat`

首条消息示例：

```json
{
  "chat_id": "demo_001",
  "type": "message",
  "content": "请分析两个版本之间的漏洞变化。"
}
```

服务端会继续追问可能缺失的参数，例如：

- `binary_filename`
- `cve_id`
- `cwe_id`
- 厂商信息

### 第三步：查看任务结果

接口：

- `GET /v1/chat_list`
- `GET /v1/tasks/{chat_id}`
- `GET /v1/tasks/{chat_id}/events`
- `GET /v1/tasks/{chat_id}/findings`

---

## 4.2 Source Diff 使用方式

Source Diff 是单独入口。

### 支持的上传后缀

当前后端白名单包括：

- `.c`
- `.cpp`
- `.cc`
- `.cxx`
- `.h`
- `.hpp`
- `.hh`
- `.hxx`
- `.js`

### 上传源码文件

接口：`POST /v1/sourceDiff/files`

```bash
curl -X POST 'http://127.0.0.1:8000/v1/sourceDiff/files' \
  -F 'chat_id=source_diff_demo' \
  -F 'file=@/path/to/old.c'

curl -X POST 'http://127.0.0.1:8000/v1/sourceDiff/files' \
  -F 'chat_id=source_diff_demo' \
  -F 'file=@/path/to/new.c'
```

### 列出源码文件

接口：`GET /v1/sourceDiff/files?chat_id=...`

```bash
curl 'http://127.0.0.1:8000/v1/sourceDiff/files?chat_id=source_diff_demo'
```

### 删除源码文件

接口：`DELETE /v1/sourceDiff/file?chat_id=...&filename=...`

```bash
curl -X DELETE 'http://127.0.0.1:8000/v1/sourceDiff/file?chat_id=source_diff_demo&filename=old.c'
```

### 发起 Source Diff 分析

接口：`WS /v1/sourceDiff/analyze`

首条消息示例：

```json
{
  "chat_id": "source_diff_demo",
  "type": "message",
  "content": "对比 old.c 和 new.c，CVE 是 CVE-2024-12345，重点看 CWE-787"
}
```

参数采集器会从多轮对话中提取：

- `file1`
- `file2`
- `cve_id`
- `cwe`
- `cve_details`

分析完成后可得到：

- HTML diff
- hunk 级安全分析结果
- 安全相关变更摘要

结果目录：

```text
history/source_diff_sessions/<chat_id>/source_diff/
```

HTML diff 静态访问路径通常类似：

```text
/static/images/temp_diffs/<file1>_vs_<file2>.html
```

---

## 4.3 Code Repair

### 上传源码文件

接口：`POST /v1/codeRepair/files`

支持后缀：

- `.c`
- `.cpp`
- `.h`
- `.hpp`

### 列表 / 删除

- `GET /v1/codeRepair/files?chat_id=...`
- `DELETE /v1/codeRepair/file?chat_id=...&filename=...`

### 发起修复

接口：`WS /v1/codeRepair/repair`

首条消息至少需要：

```json
{
  "chat_id": "repair_demo"
}
```

---

## 4.4 Hardcoded String Audit

接口：`POST /v1/hardcode_audit`

支持两种方式：

1. 直接上传文件
2. 传入已有文件路径 `file_path`

示例：

```bash
curl -X POST 'http://127.0.0.1:8000/v1/hardcode_audit' \
  -F 'chat_id=string_audit_demo' \
  -F 'file=@/path/to/sample.bin'
```

返回内容包括：

- 审计概要
- 风险等级
- 可疑字符串列表
- 本地结果目录

---

## 5. 常用接口一览

### 任务与固件分析

- `POST /v1/tasks`
- `POST /v1/files`
- `POST /v1/tasks/{chat_id}/files/{upload_role}`
- `WS /v1/chat`
- `GET /v1/chat_list`
- `GET /v1/tasks/{chat_id}`
- `GET /v1/tasks/{chat_id}/events`
- `GET /v1/tasks/{chat_id}/findings`

### 平台集成接口（供 DeepauditExtension / HustAgent 等平台调用）

当前后端还提供一组 owner-aware 的平台接口，用于由上层平台创建任务、上传文件并查询结果：

- `POST /api/platform/tasks`
- `POST /api/platform/tasks/{task_id}/files/{upload_role}`
- `POST /api/platform/tasks/{task_id}/start`
- `POST /api/platform/tasks/{task_id}/cancel`
- `GET /api/platform/tasks`
- `GET /api/platform/tasks/{task_id}`
- `GET /api/platform/tasks/{task_id}/events`
- `GET /api/platform/tasks/{task_id}/findings`

这些接口与旧的 `/v1/*` WebSocket 聊天流不同，适合平台侧以任务镜像的方式接入。典型请求会带：

- `owner_id`
- `external_task_id`
- `source`
- `old` / `new` 两个上传角色

如果你是给上层平台部署 VulnAgent，这组接口应作为主要接入面。

---

### Source Diff

- `POST /v1/sourceDiff/files`
- `GET /v1/sourceDiff/files`
- `DELETE /v1/sourceDiff/file`
- `WS /v1/sourceDiff/analyze`

### Code Repair

- `POST /v1/codeRepair/files`
- `GET /v1/codeRepair/files`
- `DELETE /v1/codeRepair/file`
- `WS /v1/codeRepair/repair`

### 审计能力

- `POST /v1/hardcode_audit`

---

## 6. 运行产物说明

默认根目录：

```text
history/
```

常见输出：

- `history/<chat_id>/`：主分析任务产物
- `history/source_diff_sessions/<chat_id>/`：Source Diff 输入目录
- `history/source_diff_sessions/<chat_id>/source_diff/`：Source Diff 输出目录
- `images/`：静态图片 / HTML diff 对外访问目录

---

## 7. 常见问题

### 7.1 `bindiff: command not found`

说明 BinDiff CLI 未正确安装或未加入 `PATH`。

### 7.2 Binwalk 解包失败

请检查：

- `binwalk` 是否已安装
- 固件格式是否需要额外插件（如 `sasquatch`、`jefferson`、`ubi-reader`）

### 7.3 无法连接 IDAService

请检查：

- Windows 服务是否已启动
- `config.ini` 中 `[IDA_SERVICE].service_url` 是否正确
- Linux 主机到 Windows 主机的网络是否可达

### 7.4 LLM 调用失败

请检查：

- `api_key` 是否正确
- `base_url` 是否可访问
- 所选 `model_name` 是否存在

### 7.5 PostgreSQL 迁移失败

请优先确认：

- `VULNAGENT_DATABASE_URL` 是否正确
- 是否安装了 `psycopg` 驱动
- 是否已执行 `alembic upgrade head`

### 7.6 跨域或反向代理后前端无法访问

请检查：

- `CORS_ALLOW_ORIGINS` 是否已按实际前端地址配置
- 反向代理是否正确转发 WebSocket
- 前端访问端口是否与你实际启动端口一致（`python main.py` 默认 8001，手动 `uvicorn` 示例为 8000）

### 7.7 平台接口调用失败

如果你通过 DeepauditExtension / HustAgent 等平台调用 `/api/platform/*` 接口，请优先确认：

- PostgreSQL 已按需执行 `alembic upgrade head`
- `owner_id` / `external_task_id` / `source` 传值正确
- 上传阶段已分别提交 `old` 和 `new` 文件
- Linux 主服务与 Windows IDAService 网络连通

---

## 8. 部署前检查清单

在新主机部署前，建议至少逐项确认：

1. 已准备 Python 3.10+ 环境并安装 `requirements.txt`
2. 已复制并配置 `config/config.ini`
3. 已配置可用的 LLM `api_key` / `base_url` / `model_name`
4. `[IDA_SERVICE].service_url` 指向可达的 Windows IDAService
5. 如使用 PostgreSQL，已设置 `VULNAGENT_DATABASE_URL` 并执行 `alembic upgrade head`
6. 如使用 SQLite，确认 `history/` 目录可写
7. 如有前端或反向代理，已配置 `CORS_ALLOW_ORIGINS`
8. 如使用平台集成，已验证 `/api/platform/*` 接口可访问

---

## 9. 开发说明

- 后端入口为 [main.py](main.py)
- Source Diff 执行逻辑位于 [agent/source_diff_agent.py](agent/source_diff_agent.py)
- Source Diff 参数采集位于 [agent/source_diff_parameter_agent.py](agent/source_diff_parameter_agent.py)
- 数据库会话与 URL 解析位于 [db/session.py](db/session.py)
- Alembic 环境位于 [migrations/env.py](migrations/env.py)

当前仓库未提供完整的后端自动化测试套件；修改后建议至少手工验证：

1. `POST /v1/files` + `WS /v1/chat`
2. `POST /v1/sourceDiff/files` + `WS /v1/sourceDiff/analyze`
3. `POST /v1/codeRepair/files` + `WS /v1/codeRepair/repair`
4. `POST /v1/hardcode_audit`

---

## 10. 许可证

请遵守本仓库以及第三方工具（如 IDA Pro、BinDiff）的许可证要求。

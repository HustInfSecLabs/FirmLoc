## VulnAgent

面向固件与二进制差异分析的多智能体系统。通过“Binwalk → IDA 反编译（远端服务）→ BinDiff 对比 → LLM 检测”流水线，自动定位不同版本固件中的潜在漏洞变化点，并输出可视化结果与分析报告。

本说明基于本地 Conda/Python 环境名称为“VulAgent”的假设，默认在 Linux 上运行主服务，Windows 侧运行 IDA 后端服务（可远程）。


## 架构与流程

- 主服务（Linux，FastAPI/uvicorn）
	- 上传固件（POST /v1/files）并按 chat_id 归档到 `history/`。
	- 通过 WebSocket（/v1/chat）驱动多智能体流水线，实时推送进度、终端命令与截图。
	- 流水线：
		1) Binwalk 提取固件文件系统
		2) Binary Filter（结合 LLM 与上下文）筛选可疑二进制
		3) 调用远端 IDAService 导出 BinExport/IDB 与伪 C
		4) 本地调用 BinDiff CLI 对比两个版本
		5) Detection Agent（LLM）对伪 C 差异进行解释与风险研判

- IDA 后端服务（Windows，Flask）
	- 负责调度本地 IDA Pro（含 BinDiff 插件）生成截图、BinExport/IDB、伪 C 代码。
	- 主服务通过 HTTP 接口访问（具体地址以 `config/config.ini` 的 `[IDA_SERVICE].service_url` 为准）。

输出产物集中在 `history/{chat_id}/` 下（含 binwalk 提取目录、ida 导出、bindiff 结果图与状态文件）。


## 环境要求

- 操作系统
	- 主服务：Linux（推荐 Ubuntu 20.04+/Debian 系列）
	- IDAService：Windows（需安装 IDA Pro 7.x 与 BinDiff 插件）

- 运行时与依赖
	- Conda：建议使用 Miniconda/Anaconda
	- Python：3.10（建议与 Conda 环境同名：VulAgent）
	- 系统工具：
		- binwalk（用于固件解包）
		- BinDiff CLI（Linux 命令行版本，用于对比两个 .BinExport）



## 快速开始

### 1) 创建 Conda 环境（VulAgent）

```bash
conda create -n VulAgent python=3.10 -y
conda activate VulAgent
```

### 2) 安装系统依赖（Linux）

```bash
# 安装 binwalk（Debian/Ubuntu 示例）
sudo apt update
sudo apt install -y binwalk

# 安装 BinDiff CLI（需从官方发布页下载 Linux 版本）
# 假设已解压到 ~/tools/bindiff，并将可执行文件加入 PATH
echo 'export PATH="$HOME/tools/bindiff:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 验证可执行
binwalk --help
bindiff --help
```

### 3) 安装 Python 依赖

```bash
cd VulnAgent

# Linux 环境
python -m pip install --upgrade pip
pip install -r requirements.txt

```

### 4) 配置 LLM 与运行目录

编辑 `config/config.ini`：

- `[LLM]` 选择模型服务（如 WenXin、Qwen、OpenAI、Claude、GLM 等），并在对应小节填入 `api_key`、`base_url`。
- `[result.path] savedir` 为运行数据根目录（默认 `history`）。
- `[CVE]` 段参数为必填：
	- `cve_id`：要复现/分析的 CVE 编号，用于情报收集阶段抓取相关信息（不可为空）。
	- `binary_filename`：需要分析的固件名（或关键标识），用于可疑文件筛选（不可为空）。

示例：

```ini
[CVE]
cve_id = CVE-2024-12345
binary_filename = Qnap HS-251
```


### 5) 配置 IDA 后端服务（Windows）

参考 `agent/IDAService/README.md`：

1. 安装并可用的 IDA Pro（例如 7.5）与 BinDiff 插件（与 IDA 版本匹配）。
2. 将 `export_binexport.py`、`export_hexrays.py` 与 `app.py` 放在同一目录；按需修改 `app.py` 中：
	 - 脚本路径（两个 export 脚本的绝对路径）
	 - IDA 可执行文件路径（如 ida64.exe）
	 - Python 环境变量（PYTHONPATH/PYTHONHOME，通常与运行 `app.py` 的解释器一致）
3. 启动：
	 ```bash
	 python app.py
	 ```

IDA 服务 URL 现已在 `config/config.ini` 中配置（无需改代码）：

```ini
[IDA_SERVICE]
service_url = http://<windows_host>:5000
```

请将 `<windows_host>` 替换为你的 Windows 机 IP/主机名（如 `10.12.xxx.xx`）。

说明：Windows 侧 IDA 后端服务需要提供以下路由，主服务会在 `service_url` 基础上拼接调用：
- `GET/POST /reversing_analyze_screenshot`（截图打包下载）
- `POST /export_binexport`（导出 BinExport/IDB）
- `POST /export_pseudo_c`（导出伪 C）

### 6) 启动主服务（Linux）

```bash
# 方式一：直接运行（默认 0.0.0.0:8000）
python main.py

# 方式二：使用 uvicorn（可自定义）
uvicorn main:app --host 0.0.0.0 --port 8000
```


## 交互与接口

### 上传固件

- 接口：`POST /v1/files`
- 表单字段：
	- `file`: 固件二进制文件（支持 .bin/.img/.elf/.tar 等常见固件与可执行格式）
	- `chat_id`: 同一轮对话/对比任务的标识（两份不同版本固件需使用相同 chat_id）

示例（可参考 `client.py`）：

```python
from client import upload_firmware
upload_firmware("/path/to/firmware_old.bin", chat_id)
upload_firmware("/path/to/firmware_new.bin", chat_id)
```

### 启动分析（WebSocket）

- 接口：`WS /v1/chat`
- 初始消息：
	```json
	{
		"chat_id": 123456,
		"type": "message",
		"content": "请根据两个版本的固件文件，分析差异并给出可能存在的漏洞和成因。"
	}
	```
- 服务会持续推送流水线阶段、命令与截图链接（`/static/images/...`）。

### 获取对话列表

- 接口：`GET /v1/chat_list`

### 代码修复模式（可选）

- 上传源文件：`POST /v1/codeRepair/files`（仅允许 .c/.cpp/.h/.hpp）
- 列表：`GET /v1/codeRepair/files?chat_id=...`
- 删除：`DELETE /v1/codeRepair/file?chat_id=...&filename=...`
- WebSocket 修复：`WS /v1/codeRepair/repair`

### 硬编码字符串审计（新）

- 接口：`POST /v1/hardcode_audit`
- 表单字段：
	- `file`: 单个二进制/固件文件（10MB 以内）
	- `chat_id` (可选)：结果保存目录标识，默认自动生成
- 行为：
	1. 后端调用远端 IDAService 提取可打印的硬编码字符串
	2. 将去重后的字符串列表发送给大模型，识别账号密码、SQL 语句、命令执行、固件/中间件名称与版本、预设/后门用户、疑似加密片段等敏感信息
- 返回：结构化 JSON，包含审计概要、风险等级、可疑字符串列表与保存的本地结果路径


## 支持的分析模式

| 模式 | 触发方式 | 流程特性 |
| --- | --- | --- |
| 固件比较（默认） | 上传两个固件/镜像文件（.bin/.img/.tar 等） | Binwalk 自动解包 → Binary Filter 从提取目录挑选可疑二进制 → IDA/BinDiff/LLM | 
| 二进制/Windows 程序比较 | 上传两个可执行文件（ELF/Mach-O/PE，例如 `.so`、`.exe`、`.dll`） | 自动跳过 Binwalk 与文件筛选，直接将用户提供的二进制对送入 IDA → BinDiff → LLM |

> 说明：当系统检测到上传的两个文件都带有 ELF/Mach-O/PE 头时，会自动切换到“二进制比较”模式，适用于 Windows 程序或已手动提取出的二进制对。若希望强制执行固件模式，只需上传原始固件镜像；若希望直接比较二进制，请确保同一个 `chat_id` 目录下仅包含那两个可执行文件，以避免歧义。


## 目录结构（节选）

```
VulnAgent/
	main.py                  # FastAPI 入口
	client.py                # 本地示例客户端（上传 + WS 收取输出）
	agent/
		VulnAgent.py           # 多智能体主流程（Binwalk → IDA → BinDiff → LLM）
		binwalk.py             # Binwalk 调用封装
		ida_toolkits.py        # 远端 IDAService HTTP 调用封装
		bindiff_agent.py       # BinDiff 结果整理与截图
		IDAService/            # Windows 侧 IDA 后端服务（Flask）
	tools/
		bindiff_tool.py        # 调用 bindiff CLI
		bindiff_visual.py      # 通过鼠标宏操控 BinDiff UI 并自动截图
	config/
		config.ini             # LLM 服务、保存目录、CVE 提示项等配置
	history/                 # 运行数据根目录（按 chat_id 分组）
	images/                  # 静态图片目录（通过 /static/images 提供）
	requirements.txt         # Python 依赖
```


## 常见问题（FAQ）

1. `bindiff: command not found`？
	 - 请先正确安装 BinDiff CLI（Linux 版），并将其路径加入 `PATH`，然后重新打开终端或 `source ~/.bashrc`。

2. IDA/Bindiff 阶段无截图或报错？
	- 确认 Windows 侧 IDAService 已启动，主机地址与端口在 `config/config.ini` 的 `[IDA_SERVICE].service_url` 配置（或通过环境变量覆盖）；
	 - 确认 IDA Pro 与 BinDiff 插件匹配；
	 - 检查 Windows 侧 export 脚本路径与权限；
	 - 若仅 CLI 对比成功但 UI 截图失败，请在 Linux 桌面环境安装 `xdotool` 与 `scrot` 并使用 X11 会话（见下文“Bindiff UI 自动截图”）。
	- 若不启用 Bindiff 截图功能，可在 `agent/bindiff_agent.py` 将调用行
	  `screenshots = bindiff_ui(..., os.path.join(self.output_dir, "images"))` 改为 `screenshots = []`。


3. Binwalk 提取为空或失败？
	 - 确认 `binwalk` 安装成功且可用；
	 - 某些固件需额外的解包依赖（如 `sasquatch`、`jefferson`、`ubi-reader` 等），请根据固件类型安装对应插件。

4. LLM 无法调用或额度不足？
	 - 检查 `config/config.ini` 中的模型服务与 `api_key` 是否正确，避免将密钥提交到仓库；
	 - 如使用企业代理或自建网关，请调整 `base_url`。

## Bindiff UI 自动截图（鼠标宏）

在 Bindiff 对比阶段，项目会调用 `tools/bindiff_visual.py` 使用鼠标宏自动化 BinDiff GUI 并截图常用视图（总览、调用图、已匹配函数、主侧未匹配、次侧未匹配）。

依赖与环境要求（Linux 桌面）：
- 已安装 BinDiff 并可通过 `bindiff -ui` 打开图形界面；
- 已安装 `xdotool` 与 `scrot`：
	```bash
	sudo apt install -y xdotool scrot
	```
- 需在 X11 会话下运行（Wayland 下请启用 XWayland 或改用等效工具）；
- 需要在能看到桌面的交互会话中运行（Server/无头环境不支持该 UI 自动化）。

工作原理（简述）：
- 启动 `bindiff -ui`，使用 `xdotool` 发送键鼠事件，按固定坐标点开/加载 `.BinDiff` 对比文件，切换到不同标签页；
- 使用 `scrot -u` 截取活动窗口，图片保存在 `history/{chat_id}/bindiff/images/` 下；
- 默认 `.BinDiff` 文件由前一步 CLI 阶段生成并临时拷贝到 `test/` 目录（由 `tools/bindiff_tool.py` 与 `agent/bindiff_agent.py` 协同完成）。

坐标与路径自定义：
- 坐标锚点与按钮位置在 `tools/bindiff_visual.py` 顶部的 `ANCHOR` 与 `COORDINATES` 中定义，建议根据你的分辨率/DPI 手动微调；
- 截图输出目录由调用方传入（默认 `history/{chat_id}/bindiff/images/`），`HOME/IMAGE_DIR/DIFF_FILE` 等常量也可按需修改；
- 如 UI 自动化对你环境不稳定，可暂时跳过该步骤，仅使用 CLI 比对与结果解析。

常见问题：
- 截图为空或总是同一张：确保 `scrot -u` 能截到当前活动窗口；必要时在截图前增加 `time.sleep` 延时；
- 点击/输入错位：调整 `ANCHOR/COORDINATES` 中的坐标，或改用窗口置顶/最大化后重新标定；
- Wayland 环境：`xdotool`/`scrot` 在原生 Wayland 支持有限，建议切换 X11 会话或启用 XWayland。


## 开发小贴士

- 产物（截图、BinExport、伪 C、BinDiff 文件）均会被拷贝到 `images/` 或 `history/{chat_id}/...`，前端可直接渲染 `/static/images/...` 链接；
- `client.py` 提供了最小化的端到端示例：上传两份固件并建立 WebSocket 会话即可复现完整流水线。


## 许可证

本项目遵循仓库内声明的相应许可证（如有）。请在使用 IDA Pro、BinDiff 等第三方工具时遵守其各自的许可协议。


## 致谢

- Binwalk、IDA Pro、BinDiff 社区
- 各大 LLM 服务提供方


# VulnAgent 离线交付

## 目录说明
- `docker-compose.yml`：离线单机启动编排
- `.env.example`：环境变量模板
- `build-image.sh`：在构建机把本机 IDA 和 BinDiff 一起打进镜像
- `start.sh`：使用已存在镜像启动服务
- `stop.sh`：停止并移除容器
- `check.sh`：本机健康检查
- `export-images.sh`：导出镜像 tar 包
- `images/`：导出的离线镜像 tar 包目录

## 交付物范围
甲方离线部署 VulnAgent 时，至少需要以下内容：
- `delivery/offline/` 整个目录
- `delivery/offline/images/` 下导出的镜像 tar 包
- `config/config.ini`
- 一份按甲方实际环境修改好的 `.env`，或让甲方基于 `.env.example` 自行修改

甲方机器不需要重新构建镜像，也不需要单独安装 IDA、BinDiff。

## 推荐交付流程
### 1. 在可联网构建机上
```bash
cd delivery/offline
cp .env.example .env
cp ../../config/config.ini.example ../../config/config.ini
# 编辑 ../../config/config.ini，填入甲方实际使用的模型配置
./build-image.sh
./export-images.sh
```

### 2. 将交付物拷贝到甲方离线服务器
建议拷贝整个 `delivery/offline/` 目录，并同时拷贝 `config/config.ini`。

### 3. 在甲方离线服务器上导入镜像
```bash
docker load -i images/vulnagent-offline_latest.tar
```

### 4. 在甲方离线服务器上修改配置并启动
```bash
cd delivery/offline
cp .env.example .env
# 如需修改端口/数据目录，编辑 .env
# 如需修改模型 API Key / Base URL / model_name，编辑 ../../config/config.ini
./start.sh
sleep 10
./check.sh
docker logs --tail 200 vulnagent-offline
```

### 5. 停止服务
```bash
cd delivery/offline
./stop.sh
```

## 交付前准备
1. 复制 `.env.example` 为 `.env`
2. 按实际环境修改 `.env` 中以下变量：
   - 构建机上至少确认：`VULNAGENT_IMAGE`、`LOCAL_IDA_SOURCE`、`LOCAL_IDA_HOME`、`LOCAL_BINDIFF_SOURCE`
   - 甲方服务器上至少确认：`VULNAGENT_IMAGE`、`VULNAGENT_PORT`、`IDA_SERVICE_PORT`、`VULNAGENT_DATA_DIR`
   - 如需自定义容器内 IDA 路径，再调整：`IDA32_PATH` / `IDA64_PATH` / `IDAT32_PATH` / `IDAT64_PATH`
   - 如需外部数据库连接串，可在 `.env` 中设置：`VULNAGENT_DATABASE_URL`
3. 准备 `../../config/config.ini`
4. 确认构建机本地 `LOCAL_IDA_SOURCE` 目录下至少存在：
   - `ida`
   - `idat`
   - `plugins/`
   - 以及 IDA 运行所需的其余文件
5. 确认构建机本地 `LOCAL_IDA_HOME` 目录下至少存在：
   - `ida.reg`
   - `plugins/`
   - 以及当前宿主机可正常无头运行 IDA 所需的其余用户配置
6. 确认构建机本地 `LOCAL_BINDIFF_SOURCE` 目录下至少存在：
   - `bin/bindiff`
   - `bin/binexport2dump`
   - 以及 BinDiff 运行所需的其余文件

## 配置文件说明

VulnAgent 离线部署涉及两个主要配置文件：
- `delivery/offline/.env`
- `config/config.ini`

### 1. `delivery/offline/.env`

#### 镜像与容器名
```env
VULNAGENT_IMAGE=vulnagent-offline:latest
VULNAGENT_CONTAINER_NAME=vulnagent-offline
```
- `VULNAGENT_IMAGE`：构建和启动时使用的镜像名
- `VULNAGENT_CONTAINER_NAME`：容器名

如果你重新打 tag 或甲方导入后镜像名不同，这里要同步修改。

#### 端口配置
```env
VULNAGENT_PORT=8001
IDA_SERVICE_PORT=5000
```
- `VULNAGENT_PORT`：对外暴露的 FastAPI 端口
- `IDA_SERVICE_PORT`：对外暴露的 IDAService 端口

访问示例：
- VulnAgent API：`http://服务器IP:8001/docs`
- IDAService 健康接口：`http://服务器IP:5000/health`

如果甲方机器端口冲突，可改成其他值，例如：
```env
VULNAGENT_PORT=18001
IDA_SERVICE_PORT=15000
```

#### 数据持久化目录
```env
VULNAGENT_DATA_DIR=~/HustAgentData
```
该目录会挂载到容器内 `/data`，用于持久化：
- 上传文件
- 分析结果
- IDA 输出
- 日志

建议改成甲方明确的数据盘路径，例如：
```env
VULNAGENT_DATA_DIR=/data/vulnagent
```

要求：
- 运行 `start.sh` 的用户对该目录有读写权限
- 目录有足够磁盘空间存放固件、分析中间产物和结果

#### 构建机本地 IDA / BinDiff 来源
以下变量只在构建机执行 `build-image.sh` 时使用，甲方服务器通常不需要改：
```env
LOCAL_IDA_SOURCE=/home/wzh/Desktop/tools/IDA
LOCAL_IDA_HOME=/home/wzh/.idapro
LOCAL_BINDIFF_SOURCE=/opt/bindiff
```

其中：
- `LOCAL_IDA_SOURCE`：本机 IDA 安装目录
- `LOCAL_IDA_HOME`：本机 IDA 用户配置目录，需包含 `ida.reg` 和 `plugins/`
- `LOCAL_BINDIFF_SOURCE`：本机 BinDiff 安装目录

如果甲方服务器不参与构建，可保持默认值不动；`start.sh` 不会读取它们。

#### 容器内 IDA 可执行路径
```env
IDA32_PATH=/opt/ida/ida
IDA64_PATH=/opt/ida/ida
IDAT32_PATH=/opt/ida/idat
IDAT64_PATH=/opt/ida/idat
```
通常无需修改，除非你打包进镜像的 IDA 路径不是 `/opt/ida`。

#### 外部数据库配置
```env
VULNAGENT_DATABASE_URL=
```
- 留空：优先走 `config.ini` 的 `[DATABASE]` 配置，并可回退到 SQLite
- 填值：容器启动时优先使用这里的 PostgreSQL 连接串

示例：
```env
VULNAGENT_DATABASE_URL=postgresql+psycopg://postgres:password@192.168.1.10:5432/vulnagent
```

#### 跨域配置
```env
CORS_ALLOW_ORIGINS=*
```
如果只在内网使用，默认通常够用；如需限制来源，可改成具体域名列表。

### 2. `config/config.ini`
容器启动时会把宿主机的 `../../config/config.ini` 挂载到容器内 `/app/config/config.ini`。因此甲方修改模型配置时，不需要进容器改文件，只要编辑宿主机上的 `config/config.ini`。

可直接从模板复制：
```bash
cp config/config.ini.example config/config.ini
```

#### 模型配置
常见会修改的模型小节包括：
- `[LLM.DeepSeek]`
- `[LLM.Claude]`
- `[LLM.GPT]`
- `[LLM.Qwen]`
- `[LLM.GLM]`

例如：
```ini
[LLM.DeepSeek]
model_name = deepseek-chat
api_key = sk-xxxxx
base_url = https://api.deepseek.com/v1
```

或：
```ini
[LLM.Claude]
model_name = claude-3-7-sonnet-20250219
api_key = sk-ant-xxxxx
base_url = https://api.anthropic.com
```

常见需要改的字段：
- `model_name`：模型名
- `api_key`：接口密钥
- `base_url`：模型服务地址；如果使用官方默认地址，可按模板填写或保持该模型默认值

如果系统实际只使用某一个模型，重点填写对应 `[LLM.xxx]` 小节即可。

#### 数据库配置
有两种方式：
- 简单离线单机：保持 `config.ini` 中 `[DATABASE]` 默认配置，允许 SQLite fallback
- 外部 PostgreSQL：在 `.env` 中设置 `VULNAGENT_DATABASE_URL`，容器启动时会优先读取它

`config.ini.example` 当前相关配置：
```ini
[DATABASE]
url =
use_sqlite_fallback = true
```

#### IDAService 配置
```ini
[IDA_SERVICE]
service_url = http://localhost:5000
```
单机离线容器默认直连本机 IDAService，通常保持默认即可。

#### ZERO_DAY_AGENT 配置
```ini
[ZERO_DAY_AGENT]
service_url = http://localhost:8000/api/v1/zero-day-agent
timeout = 14400
```
如果本次离线交付不依赖该能力，可按实际情况保留默认或在业务侧避免调用。

## 本机构建镜像
```bash
cd delivery/offline
cp .env.example .env
./build-image.sh
```

`build-image.sh` 会先校验 `.env` 里的 `LOCAL_IDA_SOURCE`、`LOCAL_IDA_HOME` 和 `LOCAL_BINDIFF_SOURCE`，确认 IDA 程序目录、IDA 用户配置目录、BinDiff 关键文件存在后，再把这些目录同步到构建上下文并执行 `docker build`。

当前离线镜像构建会基于 `requirements.txt` 自动生成一份仅供容器使用的 `requirements.offline.txt`，去掉只服务于 GUI 版 `agent/IDAService/app.py` 的依赖（如 `PyAutoGUI`、`pynput` 等），以匹配当前实际使用的 Linux 版 `agent/IDAService/app_linux.py`。

## 导出镜像
```bash
cd delivery/offline
./export-images.sh
```

导出后镜像位于 `delivery/offline/images/`。

## 启动服务
```bash
cd delivery/offline
./start.sh
```

## 健康检查
```bash
cd delivery/offline
./check.sh
```

## 修改配置后的生效方式
若已启动容器，修改 `config/config.ini` 或 `.env` 后建议执行：
```bash
cd delivery/offline
./stop.sh
./start.sh
```

## 甲方部署检查清单
启动前建议逐项确认：
1. 已安装 Docker 与 Docker Compose
2. 已成功 `docker load` 离线镜像 tar
3. `.env` 已按甲方环境修改
4. `config/config.ini` 已按实际模型配置填写
5. 宿主机数据目录已确认可写
6. 目标端口未被占用
7. 如使用外部 PostgreSQL，连接串已验证可达
8. 如与 HustAgent 联动，HustAgent 中的 `VULNAGENT_BASE_URL` 已与当前暴露端口一致

## 注意事项
- `start.sh` 默认不再执行 `docker build`，适合甲方离线服务器直接启动已导入镜像
- `docker-compose.yml` 默认把宿主机 `../../config/config.ini` 挂载到容器 `/app/config/config.ini`
- IDA 和 BinDiff 已在构建阶段打进镜像，甲方机器不需要单独安装它们
- 构建阶段还会把 `LOCAL_IDA_HOME` 指向的宿主机 IDA 用户配置打进镜像的 `/root/.idapro`，用于复用已接受 license 和用户侧配置
- 镜像构建阶段会执行 `/opt/ida/idapyswitch --force-path /usr/local/lib/libpython3.10.so.1.0`，把 IDA 的 Python runtime 固定到容器内可用的 3.10 库
- 容器内会设置 `TVHEADLESS=1`，避免 IDA CLI 在无终端重定向场景下因 TVision 报错退出
- 为避免宿主机 `~/.idapro/plugins` 中与当前镜像内 IDA 版本不兼容的 BinDiff / BinExport 用户插件覆盖镜像内插件，构建时会移除 `/root/.idapro/plugins` 下同名 `.so`，运行时优先使用 `/opt/ida/plugins`
- 若甲方服务器不参与构建，可将 `.env` 中的 `LOCAL_IDA_SOURCE`、`LOCAL_IDA_HOME`、`LOCAL_BINDIFF_SOURCE` 保持默认值不动；`start.sh` 不会读取它们
- 容器内 `bindiff` 会通过 `/opt/bindiff/bin` 自动加入 `PATH`
- 容器内同时启动两个进程：
  - VulnAgent FastAPI：`8001`
  - IDAService：`5000`
- 若不提供 `VULNAGENT_DATABASE_URL`，默认走 `config.ini` 配置，并可回退到 SQLite
- `check.sh` 依赖本机可访问 `curl` 和 `docker compose`
- 旧版本镜像不会自动带上新的 BinDiff/IDA 修复；如修改过 Dockerfile、构建脚本、`.env.example` 或 README 后重新交付，需重新执行一次 `./build-image.sh` 和 `./export-images.sh`

## 常见问题与排查

### 1. `docker run ... sh -lc ...` 没有执行预期 shell，而是直接起服务
这是因为镜像设置了 `ENTRYPOINT ["/app/docker/offline/entrypoint.sh"]`。

如需进入 shell 检查，应用：
```bash
docker run --rm --entrypoint sh vulnagent-offline:latest -lc 'your command'
```

### 2. binwalk 报 `invalid interpolation syntax`
通常是旧镜像仍在运行，或镜像中还没有带上最新 `VulnAgent/agent/binwalk.py` 修复。

本次修复包括：
- `binwalk -Me` 改为 `binwalk --run-as=root -Me`
- `ConfigParser()` 改为 `RawConfigParser()`

如果甲方还在使用旧镜像，需要重新：
```bash
./build-image.sh
./export-images.sh
```
然后在甲方重新 `docker load` 和 `./start.sh`。

### 3. binwalk 提示缺少 `unsquashfs` / `sasquatch` / `yaffshiv`
当前镜像已补充 `squashfs-tools`，可提供 `unsquashfs`。

但如果固件提取过程仍依赖：
- `sasquatch`
- `yaffshiv`
等额外第三方提取工具，而镜像里没有对应程序，就仍可能看到警告。

这类警告是否影响最终分析，要看目标固件是否确实依赖这些提取链路。

### 4. IDA/BinExport 报 `Python 3 is not configured`
本次离线镜像已在构建阶段固化：
```bash
/opt/ida/idapyswitch --force-path /usr/local/lib/libpython3.10.so.1.0
```

如果甲方仍看到类似报错，优先检查：
- 是否确实使用了最新重建后的镜像
- 旧容器是否已经停止并替换
- `docker load` 导入后，`VULNAGENT_IMAGE` 是否还是旧 tag

### 5. IDA 报 `License not yet accepted, cannot run in batch mode`
通常说明构建时没有把可用的 `LOCAL_IDA_HOME`（含 `ida.reg`）打进镜像，或打进去的配置不完整。

优先检查：
- `LOCAL_IDA_HOME` 是否指向正确的宿主机 `.idapro`
- 里面是否有 `ida.reg`
- 重新构建时是否真的用了最新 `.env`

### 6. 重新交付新镜像后，甲方旧容器怎么处理
建议顺序：
```bash
cd delivery/offline
./stop.sh
# 重新 docker load 新镜像
./start.sh
```

如需清理旧镜像，可再执行：
```bash
docker image rm <旧镜像名>
```

### 7. 与 HustAgent 联动时无法访问 VulnAgent
重点检查：
- VulnAgent 宿主机端口是否真的暴露，例如 `8001`
- HustAgent `.env` 中 `VULNAGENT_BASE_URL` 是否与当前 VulnAgent 地址一致
- 服务器防火墙 / 安全组是否放通
- `curl http://127.0.0.1:8001/docs` 或实际 IP 地址是否可达

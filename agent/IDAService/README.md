# IDA 后端服务

## 文件说明

| 文件                     | 描述                              | 备注                                                                 |
|--------------------------|-----------------------------------|----------------------------------------------------------------------|
| `app.py`                 | IDA 后端服务主程序               | 基于 Flask 创建                                                     |
| `export_binexport.py`    | 导出 BinExport 和 IDB 文件的脚本 | 需配合 [BinDiff](https://github.com/google/bindiff/releases) 插件使用（本例为 IDA Pro 7.5 + [BinDiff7](https://github.com/google/bindiff/releases/download/v7/bindiff7.msi)） |
| `export_hexrays.py`      | 导出伪 C 代码的脚本              | —                                                                   |
| `IDA_Pro_v7.5_Portable.zip` | IDA Pro 7.5 绿色版              | —                                                                   |
| `bindiff7.msi`           | BinDiff7 Windows 安装包          | —                                                                   |

## 使用说明

1. **安装与配置 IDA 和 BinDiff**  
   - 解压 `IDA_Pro_v7.5_Portable.zip`。  
   - 安装 `bindiff7.msi`。  
   - 复制插件文件：  
     - 将 `path\to\BinDiff\Plugins\IDA Pro\` 下的四个插件文件复制到 `path\to\IDA_Pro_v7.5_Portable\plugins\` 目录中。  

2. **部署脚本**  
   - 将 `export_binexport.py` 和 `export_hexrays.py` 下载至与 `app.py` 相同的目录下。  

3. **配置环境**  
   - 修改 `app.py` 中的以下参数：  
     - 脚本路径（`export_binexport.py` 和 `export_hexrays.py` 的绝对路径）。  
     - IDA 可执行文件路径（如 `IDA_Pro_v7.5_Portable\ida64.exe`）。  
     - `PYTHONPATH` 和 `PYTHONHOME`（与启动后端的 Python 解释器保持一致即可）。  

4. **启动服务**  
   ```bash
   python app.py
   ```

## appnew.py：免上传 BinExport + 批量 BinDiff

`appnew.py` 在保留原有 `binary_name`（当天 `ida_output/<YYYYMMDD>/`）模式的同时，新增支持直接对服务器文件系统上的二进制导出 BinExport，并提供批量 bindiff 接口。

### 1) 直接导出 BinExport（不需要先 upload）

POST `/export_binexport`

- `input_file_path`: 服务器上的二进制绝对路径
- `output_dir`(可选): 工作目录（推荐，用于把 IDA 产生的中间文件/导出文件放在缓存目录）
- `copy_to_output_dir`(可选, 默认 `1`): 复制二进制到 `output_dir` 再跑 IDA（避免污染原目录）
- `cleanup`(可选): 是否删除 `.i64/.idb/.id0/...` 等缓存文件（默认仅在 `output_dir`/legacy 目录下清理）

### 2) 批量对 modified/{old,new} 做 BinDiff 并统计变更函数数

POST `/batch_bindiff_modified`

参数（JSON 或 form 均可）：
- `task_dir`：包含 `extracted_diff_files/modified/{old,new}/` 的目录
  - 或传 `modified_dir`：包含 `{old,new}/` 的目录
  - 或显式传 `old_dir` + `new_dir`
- `output_dir`(可选)：默认在 `task_dir/bindiff_batch_cache`
- `old_prefix/new_prefix`(可选)：默认 `old_` / `new_`
- `bindiff_cli`(可选)：BinDiff 命令行路径；也可通过环境变量 `BINDIFF_CLI` 设置

返回 JSON：
- `total_changed_functions_sum`：所有二进制对的 `similarity != 1.0` 的函数数量之和
- `details`：每一对的统计明细

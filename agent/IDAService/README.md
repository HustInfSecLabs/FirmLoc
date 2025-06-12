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

from typing import List
from pathlib import Path
import shutil
import os
import base64
from datetime import datetime

from log import logger


def looks_like_firmware(file_path: str, min_size: int = 64 * 1024) -> bool:
    """启发式判断一个无/非标准扩展名的文件是否像固件镜像。
    判据：
    - 尺寸阈值（默认 >=64KB）避免将小型文本/配置文件误判。
    - 常见压缩/打包/文件系统/镜像魔数（gzip/xz/bzip2/zstd/lz4/tar/cpio/squashfs/jffs2/ubi/uImage 等）。
    - 回退到二进制启发式检测（is_binary_file）。

    返回 True 表示高度可疑为固件或固件容器。
    """
    try:
        size = os.path.getsize(file_path)
        if size < min_size:
            return False

        # 读取足够覆盖 tar 的 ustar 位置（偏移 257），再多读一点余量
        with open(file_path, 'rb') as f:
            head = f.read(560)

        # 压缩格式
        if head.startswith(b"\x1f\x8b"):  # gzip
            return True
        if head.startswith(b"\xFD7zXZ\x00"):  # xz
            return True
        if head.startswith(b"BZh"):  # bzip2
            return True
        if head.startswith(b"\x28\xB5\x2F\xFD"):  # zstd
            return True
        if head.startswith(b"\x04\x22\x4D\x18"):  # lz4 frame
            return True
        if head.startswith(b"\x5d\x00\x00\x80\x00"):  # lzma (常见 header)
            return True

        # 打包/归档
        if len(head) >= 262 and head[257:262] == b"ustar":  # tar
            return True
        if head[:6] in {b"070701", b"070702", b"070707"}:  # cpio(newc/crc/odc)
            return True

        # 常见固件/文件系统镜像魔数
        if head.startswith(b"\x27\x05\x19\x56"):  # U-Boot uImage
            return True
        # squashfs 魔数在头部可见为 hsqs 或 sqsh（不同端序展示）
        if head.find(b"hsqs", 0, 64) != -1 or head.find(b"sqsh", 0, 64) != -1:
            return True
        # JFFS2 常见节点魔数 0x1985（小端 0x85 0x19），不完全可靠，但可作为弱信号
        if head.startswith(b"\x85\x19"):
            return True
        # UBI/UBIFS 头部常见标识
        if head.find(b"UBI#", 0, 64) != -1:
            return True
        # cramfs 魔数 0x28cd3d45（字节序列 E=\xcd( 常见于头部）
        if head.find(b"E=\xcd(", 0, 64) != -1:
            return True

        # 名称启发式（配合尺寸阈值）
        lower_name = os.path.basename(file_path).lower()
        name_hints = (
            "rootfs", "kernel", "uimage", "image", "firmware",
            "sysupgrade", "factory", "squashfs", "ubi", "ubifs",
        )
        if any(h in lower_name for h in name_hints):
            return True

        # 回退：一般二进制/可执行的启发式（ELF/PE 或高二进制特征）
        return is_binary_file(file_path)
    except Exception:
        # 保守处理：发生异常时不认为是固件
        return False


def get_firmware_files(directory: str, recursive: bool = False) -> List:
        """
    获取指定目录下的固件文件（支持无扩展名的固件，如 rootfs2）。
        :param directory: 目标目录路径
        :param recursive: 是否递归搜索子目录
        :return: 匹配的固件文件路径列表
        """
        # 常见固件文件扩展名（可根据实际需求扩展）
        firmware_extensions = {
            '.bin',  # 二进制固件
            '.hex',  # Intel HEX格式
            '.fw',   # 通用固件扩展
            '.img',  # 镜像文件
            '.rom',  # BIOS/UEFI固件
            '.dfu',  # DFU固件
            '.cab',  # Windows更新包
            '.tar',  # 打包固件
            '.gz',   # 压缩固件
            '.upd',  # 通用更新文件
            '.w',
            '.exe',  # Windows 可执行
            '.dll',  # Windows 动态库
            '.so',   # Linux 共享库（用于已解包的二进制）
        }

        # 验证目录是否存在
        if not os.path.exists(directory):
            raise FileNotFoundError(f"目录不存在: {directory}")
        
        # 使用pathlib处理路径
        base_path = Path(directory)
        firmware_files = []

        # 选择遍历模式
        if recursive:
            file_iterator = base_path.rglob('*')  # 递归遍历
        else:
            file_iterator = base_path.glob('*')    # 仅当前目录

        # 遍历文件系统
        for item in file_iterator:
            try:
                # 过滤：必须是文件，且扩展名匹配
                if item.is_file():
                    suffix = item.suffix.lower()
                    # 1) 扩展名直接命中
                    if suffix in firmware_extensions:
                        firmware_files.append(str(item.resolve()))
                        continue
                    # 2) 无扩展名或非常见扩展名，进行启发式判定
                    if suffix == '' or suffix not in firmware_extensions:
                        if looks_like_firmware(str(item)):
                            firmware_files.append(str(item.resolve()))
            except (PermissionError, OSError) as e:
                # 处理无法访问的文件
                logger.warning(f"跳过无法访问的文件: {item} - {str(e)}")
                continue
        # （按文件名升序）
        firmware_files.sort(key=lambda x: x.lower())
        return firmware_files



def _generate_unique_name(src_file: str, dest_dir: str) -> str:
    """生成带序号的不重复文件名"""
    # 拆分文件名和扩展名
    base_name = os.path.basename(src_file)
    name_part, ext = os.path.splitext(base_name)
    
    counter = 1
    new_name = base_name
    
    while True:
        dest_path = os.path.join(dest_dir, new_name)
        if not os.path.exists(dest_path):
            return new_name
        
        # 生成带序号的新文件名
        new_name = f"{name_part}{counter}{ext}"
        counter += 1
def copy_file(src_file: str, dest_dir: str) -> str:
    """复制文件到目标目录"""
    try:
        # 验证源文件存在
        if not os.path.isfile(src_file):
            raise FileNotFoundError(f"源文件不存在: {src_file}")

        # 创建目标目录
        os.makedirs(dest_dir, exist_ok=True)
        
        # 生成唯一文件名
        unique_name = _generate_unique_name(src_file, dest_dir)
        dest_file = os.path.join(dest_dir, unique_name)

        # 执行复制（保留元数据）
        shutil.copy2(src_file, dest_file)
        logger.info(f"文件复制成功: {src_file} -> {dest_file}")
        return dest_file
    except Exception as e:
        logger.error(f"复制文件时发生错误: {str(e)}")
        raise
        

def cleanup_dir(dst_dir):
    """
    删除 dst_dir 下的所有文件（不删除子目录）。
    """
    dst_dir = Path(dst_dir)
    for file_path in dst_dir.iterdir():
        if file_path.is_file():
            try:
                file_path.unlink()
                logger.info(f"已删除：{file_path.name}")
            except Exception as e:
                logger.info(f"[错误] 删除文件失败 {file_path.name}：{e}")



def rename_file_with_b64_timestamp(file_path):
    """
    将文件名重命名为base64编码+时间戳格式(保留扩展名)
    
    参数：
    file_path : 原始文件的相对/绝对路径
    
    返回：
    new_path : 重命名后的新路径
    """
    # 分割目录和完整文件名
    directory = os.path.dirname(file_path)
    full_name = os.path.basename(file_path)
    
    # 拆分文件名和扩展名
    basename, ext = os.path.splitext(full_name)
    
    # 生成base64编码文件名（URL安全格式）
    encoded_name = base64.urlsafe_b64encode(basename.encode()).decode().rstrip('=')
    
    # 生成时间戳（格式：YYYYMMDDHHMMSS）
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # 构建新文件名
    new_filename = f"{encoded_name}_{timestamp}{ext}"
    
    # 组合新路径
    new_path = os.path.join(directory, new_filename)
    
    # 执行重命名
    os.rename(file_path, new_path)
    logger.info(f"文件重命名成功: {file_path} -> {new_path}")
    return new_path

def get_binary_architecture(file_path: str) -> str:
    """
    检测二进制文件的架构（32位或64位），返回对应的 IDA 版本
    
    Args:
        file_path: 二进制文件路径
        
    Returns:
        str: "ida" (32位), "ida64" (64位), 或 "ida64" (默认/无法识别时)
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(64)  # 读取足够的字节来判断
            
            if len(header) < 5:
                logger.warning(f"文件太小，无法判断架构: {file_path}，默认使用 ida64")
                return "ida64"
            
            # ELF 文件格式判断
            if header.startswith(b'\x7FELF'):
                # ELF 类型在第5个字节 (offset 4)
                # 1 = 32-bit, 2 = 64-bit
                ei_class = header[4]
                if ei_class == 1:
                    logger.info(f"检测到 32位 ELF 文件: {file_path}")
                    return "ida"
                elif ei_class == 2:
                    logger.info(f"检测到 64位 ELF 文件: {file_path}")
                    return "ida64"
                else:
                    logger.warning(f"未知 ELF 类型: {ei_class}，默认使用 ida64")
                    return "ida64"
            
            # PE 文件格式判断 (Windows)
            elif header.startswith(b'MZ'):
                # PE header offset at 0x3C
                if len(header) >= 0x3C + 4:
                    pe_offset = int.from_bytes(header[0x3C:0x3C+4], byteorder='little')
                    
                    # 需要读取更多字节来获取 PE 头信息
                    f.seek(0)
                    pe_data = f.read(pe_offset + 24)
                    
                    if len(pe_data) >= pe_offset + 24:
                        # 检查 PE 签名
                        if pe_data[pe_offset:pe_offset+4] == b'PE\0\0':
                            # Machine type at PE_offset + 4
                            machine_type = int.from_bytes(
                                pe_data[pe_offset+4:pe_offset+6], 
                                byteorder='little'
                            )
                            # 0x014c = IMAGE_FILE_MACHINE_I386 (32-bit)
                            # 0x8664 = IMAGE_FILE_MACHINE_AMD64 (64-bit)
                            if machine_type == 0x014c:
                                logger.info(f"检测到 32位 PE 文件: {file_path}")
                                return "ida"
                            elif machine_type == 0x8664:
                                logger.info(f"检测到 64位 PE 文件: {file_path}")
                                return "ida64"
                
                logger.warning(f"无法确定 PE 文件架构，默认使用 ida64: {file_path}")
                return "ida64"
            
            # Mach-O 文件格式判断 (macOS)
            elif header[:4] in [b'\xFE\xED\xFA\xCE', b'\xCE\xFA\xED\xFE']:
                # 32-bit Mach-O
                logger.info(f"检测到 32位 Mach-O 文件: {file_path}")
                return "ida"
            elif header[:4] in [b'\xFE\xED\xFA\xCF', b'\xCF\xFA\xED\xFE']:
                # 64-bit Mach-O
                logger.info(f"检测到 64位 Mach-O 文件: {file_path}")
                return "ida64"
            
            # 未知格式，默认使用 64 位
            logger.warning(f"未识别的文件格式，默认使用 ida64: {file_path}")
            return "ida64"
            
    except Exception as e:
        logger.error(f"检测文件架构时发生错误: {file_path}, {str(e)}")
        return "ida64"  # 出错时默认使用 64 位


def is_binary_file(file_path: str) -> bool:
    """Check if a file is a binary executable (ELF, PE) or non-text file.
    Args:
        file_path: Path to the file.
    Returns:
        True if the file is a binary executable or high-entropy data, False otherwise.
    """
    with open(file_path, 'rb') as f:
        # Read the first 1024 bytes for analysis
        chunk = f.read(1024)
        if not chunk:
            return False  # Empty file

        # Check for executable file signatures
        if len(chunk) >= 4:
            # ELF format (Linux)
            if chunk.startswith(b'\x7FELF'):
                return True
            # PE format (Windows)
            if chunk.startswith(b'MZ'):
                # Check for PE header offset (0x3C) and 'PE\0\0' signature
                pe_header_offset = chunk[0x3C:0x3C+4]
                if len(pe_header_offset) == 4:
                    pe_offset = int.from_bytes(pe_header_offset, byteorder='little')
                    if pe_offset + 4 <= len(chunk):
                        if chunk[pe_offset:pe_offset+4] == b'PE\0\0':
                            return True
            # Optional: Mach-O (macOS)
            # if chunk.startswith(b'\xFE\xED\xFA\xCE') or chunk.startswith(b'\xCF\xFA\xED\xFE'):
            #     return True

        # Fallback to heuristic binary detection
        # 1. Check for NULL bytes (common in binaries)
        if b'\x00' in chunk:
            return True
        # 2. Check for high non-text character ratio
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
        non_text = chunk.translate(None, text_chars)
        if len(non_text) / len(chunk) > 0.3:
            return True

    return False


# ==================== JSON 解析工具 ====================

def strip_markdown_code_block(content: str) -> str:
    """移除markdown代码块标记"""
    content = content.strip()
    if content.startswith('```json'):
        content = content[7:].strip()
    elif content.startswith('```'):
        content = content[3:].strip()
    if content.endswith('```'):
        content = content[:-3].strip()
    return content


def find_json_object_end(content: str) -> int:
    """
    找到第一个完整JSON对象的结束位置
    
    使用状态机方式匹配括号,正确处理字符串内的引号和转义字符
    
    Args:
        content: 以'{'开头的字符串
        
    Returns:
        JSON对象的结束位置(不包含),如果未找到返回0
    """
    if not content or not content.startswith('{'):
        return 0
    
    brace_count = 0
    in_string = False
    escape_next = False
    
    for i, char in enumerate(content):
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\':
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return i + 1
    
    return 0


def extract_first_json(content: str) -> dict:
    """
    从内容中提取第一个JSON对象
    
    Args:
        content: 可能包含JSON的文本内容
        
    Returns:
        解析后的字典,如果解析失败返回空字典
    """
    import json
    
    cleaned = strip_markdown_code_block(content)
    if not cleaned.startswith('{'):
        return {}
    
    json_end = find_json_object_end(cleaned)
    if json_end == 0:
        return {}
    
    try:
        return json.loads(cleaned[:json_end])
    except json.JSONDecodeError:
        return {}


def severity_to_score(severity: str) -> int:
    """
    将严重程度字符串转换为数字分数
    
    Args:
        severity: 严重程度字符串 (Critical/High/Medium/Low等)
        
    Returns:
        对应的分数 (8/5/2/0)
    """
    severity_lower = severity.lower() if severity else ""
    if severity_lower in ["critical", "high"]:
        return 8
    elif severity_lower in ["medium", "moderate"]:
        return 5
    elif severity_lower in ["low", "minor"]:
        return 2
    return 0

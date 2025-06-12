from typing import List
from pathlib import Path
import shutil
import os
import base64
from datetime import datetime

from log import logger


def get_firmware_files(directory: str, recursive: bool = False) -> List:
        """
        获取指定目录下的固件文件
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
                if item.is_file() and item.suffix.lower() in firmware_extensions:
                    firmware_files.append(str(item.resolve()))
            except (PermissionError, OSError) as e:
                # 处理无法访问的文件
                print(f"跳过无法访问的文件: {item} - {str(e)}")
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

def is_binary_file(file_path: str) -> bool:
        r"""Check if a file is a binary file based on its content."""
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                return True
            text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
            if not chunk:
                return False
            if float(len(chunk.translate(None, text_chars))) / len(chunk) > 0.3:
                return True
            return False
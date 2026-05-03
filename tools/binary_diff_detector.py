# VulnAgent/tools/binary_diff_detector.py

import os
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
from log import logger


def compute_file_hash(file_path: str) -> str:
    """计算文件的SHA256哈希值"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.warning(f"计算文件哈希失败 {file_path}: {str(e)}")
        return ""


def find_modified_binaries(old_firmware_path: str, new_firmware_path: str, 
                           binary_list: List[str] = None) -> Dict[str, Dict]:
    """
    比较两个固件版本中的二进制文件，找出修改过的文件
    
    Args:
        old_firmware_path: 旧版本固件的解压路径
        new_firmware_path: 新版本固件的解压路径
        binary_list: 可选的二进制文件列表（相对路径），如果为None则自动扫描
    
    Returns:
        Dict[str, Dict]: 修改过的二进制文件信息
        {
            "modified": [
                {
                    "relative_path": "usr/bin/httpd",
                    "name": "httpd",
                    "old_path": "/path/to/old/usr/bin/httpd",
                    "new_path": "/path/to/new/usr/bin/httpd",
                    "old_size": 12345,
                    "new_size": 12567,
                    "old_hash": "abc123...",
                    "new_hash": "def456...",
                    "change_type": "modified"  # modified | added | removed
                }
            ],
            "added": [...],
            "removed": [...],
            "unchanged": [...]
        }
    """
    old_path = Path(old_firmware_path)
    new_path = Path(new_firmware_path)
    
    result = {
        "modified": [],
        "added": [],
        "removed": [],
        "unchanged": []
    }
    
    if not old_path.exists() or not new_path.exists():
        logger.error(f"固件路径不存在: old={old_firmware_path}, new={new_firmware_path}")
        return result
    
    # 如果没有提供binary_list，则扫描所有文件
    if binary_list is None:
        binary_list = []
        # 扫描旧固件中的所有文件
        for root, _, files in os.walk(old_path):
            for filename in files:
                file_path = Path(root) / filename
                try:
                    relative_path = file_path.relative_to(old_path)
                    binary_list.append(str(relative_path))
                except ValueError:
                    continue
        
        # 扫描新固件中的所有文件（查找新增的文件）
        for root, _, files in os.walk(new_path):
            for filename in files:
                file_path = Path(root) / filename
                try:
                    relative_path = file_path.relative_to(new_path)
                    if str(relative_path) not in binary_list:
                        binary_list.append(str(relative_path))
                except ValueError:
                    continue
    else:
        # 如果提供了binary_list，还需要检查新固件中是否有新增的文件
        # 但只检查那些在旧固件中不存在的文件（真正的新增文件）
        binary_list_set = set(binary_list)
        for root, _, files in os.walk(new_path):
            for filename in files:
                file_path = Path(root) / filename
                try:
                    relative_path = str(file_path.relative_to(new_path))
                    # 只添加不在指定列表中且在旧固件中也不存在的文件（新增文件）
                    if relative_path not in binary_list_set:
                        old_file = old_path / relative_path
                        if not old_file.exists():
                            # 确实是新增的文件
                            binary_list.append(relative_path)
                except ValueError:
                    continue
    
    logger.info(f"开始比较 {len(binary_list)} 个二进制文件...")
    
    # 遍历所有二进制文件
    for relative_path in binary_list:
        relative_path = os.path.normpath(relative_path.lstrip("./"))
        old_file = old_path / relative_path
        new_file = new_path / relative_path
        
        file_name = Path(relative_path).name
        
        # 旧版本存在，新版本也存在
        if old_file.exists() and new_file.exists():
            try:
                old_size = old_file.stat().st_size
                new_size = new_file.stat().st_size
                
                # 如果文件大小不同，直接判定为修改
                if old_size != new_size:
                    result["modified"].append({
                        "relative_path": relative_path,
                        "name": file_name,
                        "old_path": str(old_file),
                        "new_path": str(new_file),
                        "old_size": old_size,
                        "new_size": new_size,
                        "old_hash": "",
                        "new_hash": "",
                        "change_type": "modified",
                        "reason": f"文件大小变化: {old_size} → {new_size} bytes"
                    })
                    continue
                
                # 文件大小相同，需要计算哈希值
                old_hash = compute_file_hash(str(old_file))
                new_hash = compute_file_hash(str(new_file))
                
                if old_hash and new_hash and old_hash != new_hash:
                    result["modified"].append({
                        "relative_path": relative_path,
                        "name": file_name,
                        "old_path": str(old_file),
                        "new_path": str(new_file),
                        "old_size": old_size,
                        "new_size": new_size,
                        "old_hash": old_hash[:16] + "...",
                        "new_hash": new_hash[:16] + "...",
                        "change_type": "modified",
                        "reason": "文件内容变化（哈希不同）"
                    })
                else:
                    result["unchanged"].append({
                        "relative_path": relative_path,
                        "name": file_name,
                        "change_type": "unchanged"
                    })
            except Exception as e:
                logger.warning(f"比较文件失败 {relative_path}: {str(e)}")
                continue
        
        # 旧版本存在，新版本不存在（已删除）
        elif old_file.exists() and not new_file.exists():
            result["removed"].append({
                "relative_path": relative_path,
                "name": file_name,
                "old_path": str(old_file),
                "new_path": None,
                "change_type": "removed",
                "reason": "新版本中已删除"
            })
        
        # 旧版本不存在，新版本存在（新增）
        elif not old_file.exists() and new_file.exists():
            result["added"].append({
                "relative_path": relative_path,
                "name": file_name,
                "old_path": None,
                "new_path": str(new_file),
                "change_type": "added",
                "reason": "新版本中新增"
            })
    
    logger.info(f"二进制差异统计: 修改={len(result['modified'])}, "
                f"新增={len(result['added'])}, 删除={len(result['removed'])}, "
                f"未变化={len(result['unchanged'])}")
    
    return result


def format_diff_summary(diff_result: Dict[str, List[Dict]]) -> str:
    """格式化差异摘要为可读文本"""
    lines = []
    lines.append("=" * 60)
    lines.append("二进制文件差异摘要")
    lines.append("=" * 60)
    
    if diff_result["modified"]:
        lines.append(f"\n修改的文件 ({len(diff_result['modified'])} 个):")
        for i, item in enumerate(diff_result["modified"], 1):
            lines.append(f"  {i}. {item['relative_path']}")
            lines.append(f"     原因: {item['reason']}")
    
    if diff_result["added"]:
        lines.append(f"\n新增的文件 ({len(diff_result['added'])} 个):")
        for i, item in enumerate(diff_result["added"], 1):
            lines.append(f"  {i}. {item['relative_path']}")
    
    if diff_result["removed"]:
        lines.append(f"\n删除的文件 ({len(diff_result['removed'])} 个):")
        for i, item in enumerate(diff_result["removed"], 1):
            lines.append(f"  {i}. {item['relative_path']}")
    
    if diff_result["unchanged"]:
        lines.append(f"\n未变化的文件: {len(diff_result['unchanged'])} 个 (已跳过)")
    
    lines.append("=" * 60)
    return "\n".join(lines)


def get_modified_binaries_list(diff_result: Dict[str, List[Dict]], 
                                include_added: bool = False,
                                include_removed: bool = False) -> List[str]:
    """
    从差异结果中提取修改过的二进制文件路径列表
    
    Args:
        diff_result: find_modified_binaries返回的差异结果
        include_added: 是否包含新增的文件
        include_removed: 是否包含删除的文件
    
    Returns:
        List[str]: 相对路径列表
    """
    modified_list = []
    
    # 总是包含修改的文件
    for item in diff_result.get("modified", []):
        modified_list.append(item["relative_path"])
    
    # 可选：包含新增的文件
    if include_added:
        for item in diff_result.get("added", []):
            modified_list.append(item["relative_path"])
    
    # 可选：包含删除的文件
    if include_removed:
        for item in diff_result.get("removed", []):
            modified_list.append(item["relative_path"])
    
    return modified_list

from mdutils import MdUtils
from pathlib import Path
import time
from datetime import datetime
from typing import List

class PlanManager:
    def __init__(self, plan_path: str, query: str, upload_files: str, plan: str):
        """
        初始化任务规划管理器
        :param plan_path: 任务规划文件路径
        :param query: 用户请求
        :param upload_files: 用户上传文件
        :param plan: 任务规划内容
        """
        self.plan_path = plan_path
        self.query = query
        self.upload_files = upload_files
        self.plan = plan
        self._init_md()

    def _init_md(self):
        """
        初始化 Markdown 文件
        """
        self.md_file = MdUtils(file_name=self.plan_path, title='VulnAgent Plan')
        self.md_file.new_paragraph(f"用户请求任务: {self.query}")
        self.md_file.new_paragraph("用户上传文件:")
        upload_files = self._parse_list(self.upload_files)
        for file in upload_files:
            file = file.strip()
            if file:
                print(f"file: {file}")
                file_path = Path(file)
                stat = file_path.stat()
                self.md_file.new_list([f"{file}: {stat.st_size/1024} KB, {datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M')}\n"])
        self.md_file.new_paragraph(f"任务规划内容:\n{self.plan}")

        self.md_file.create_md_file()

    def _parse_list(self, raw_str: str) -> List[str]:
        """字符串转列表"""
        return [a.strip() for a in raw_str.split(',') if a.strip()] if raw_str else []
    
    def add_plan(self, plan: str):
        """
        添加任务规划内容
        :param plan: 任务规划内容
        """
        self.md_file.new_paragraph(f"{plan}")
        self.md_file.create_md_file

    def add_result(self, result: str):
        """
        添加任务结果
        :param result: 任务结果
        """
        self.md_file.new_paragraph(f"任务结果:\n{result}")
        self.md_file.create_md_file()
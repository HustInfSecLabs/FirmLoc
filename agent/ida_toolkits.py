import logging
import os
import tempfile, zipfile
from typing import List
import requests
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import io

from camel.toolkits.base import BaseToolkit
from camel.toolkits.function_tool import FunctionTool

from utils.utils import copy_file

logger = logging.getLogger(__name__)


# 可上传至Github合并的版本，已测试可行

class IdaToolkit(BaseToolkit):
    r"""A class representing a toolkit for Ida binary analysis."""

    def _show_screenshot(self, image_data: bytes):
        """显示截图弹窗"""
        try:
            # 创建临时窗口显示截图
            root = tk.Tk()
            root.title("Analysis Screenshot Preview")
            
            # 从字节数据加载图片
            image = Image.open(io.BytesIO(image_data))
            photo = ImageTk.PhotoImage(image)
            
            # 显示图片
            label = tk.Label(root, image=photo)
            label.image = photo  # 保持引用
            label.pack()
            
            # 添加确认按钮
            def on_continue():
                root.destroy()
            
            btn = tk.Button(root, text="Continue Analysis", command=on_continue)
            btn.pack(pady=10)
            
            root.mainloop()
        except Exception as e:
            logger.error(f"Failed to show screenshot: {str(e)}")
            messagebox.showerror("Error", f"Failed to display screenshot: {str(e)}")

    def analyze_binary(self, input_file_path: str, output_dir: str = None, 
                    ida_version: str = "ida32",
                    bin_export_url: str = "http://10.12.189.52:5000/export_binexport",
                    screenshot_url: str = "http://10.12.189.52:5000/reversing_analyze_screenshot",
                    pseudo_c_url = "http://10.12.189.52:5000/export_pseudo_c") -> bool:
        r"""Analyze a binary file using IDA Pro through HTTP API endpoints.
    
            This function submits the binary to multiple analysis endpoints to generate:
            - BinExport files
            - Screenshots of the disassembly
            - Pseudo-C code decompilation

        Args:
            input_file_path (str): The path to the binary file to analyze.
            output_file_path (str, optional): The path to save the analysis results, include screenshots, BinExport, pseudo_c. 
                Defaults to None, in which case it will be saved in the same path with `<input_file_path>`. 
            ida_version (str, optional): The version of IDA to use ("ida32" or "ida64"). 
                Defaults to "ida32". 
            bin_export_url (str, optional): The HTTP API endpoint for analysis. 
                Defaults to "http://10.12.189.52:5000/export_binexport". 
            screenshot_url (str, optional): The HTTP API endpoint for disassembly screenshots. 
                Defaults to "http://10.12.189.52:5000/reversing_analyze_screenshot". 
            pseudo_c_url (str, optional): The HTTP API endpoint for pseudo-C decompilation. 
                Defaults to "http://10.12.189.52:5000/export_pseudo_c". 

        Returns:
            bool: True if the analysis was successful, False otherwise.
        """

        file_name = os.path.basename(input_file_path)
        file_dir = os.path.dirname(input_file_path)

        # Validate ida_version parameter
        if ida_version.lower() not in ["ida32", "ida64"]:
            raise ValueError(f"Invalid ida_version: {ida_version}. Must be 'ida32' or 'ida64'")

        # Set default output file path if not provided
        if output_dir is None:
            output_dir = f"{file_dir}"
        
        # Check if input file exists
        if not os.path.exists(input_file_path):
            raise FileNotFoundError(f"Input file does not exist: {input_file_path}")
        
        # Create temporary directory for extracted screenshots
        screenshot_dir = os.path.join(output_dir, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)

        try:
            # 1. First send to screenshot service to get screenshots
            with open(input_file_path, 'rb') as f:
                files = {'file': (file_name, f)}
                logger.info(f"[1/3], Sending file to screenshot service: {screenshot_url}")
                screenshot_response = requests.post(screenshot_url, files=files)
            
            if screenshot_response.status_code != 200:
                logger.warning(f"Screenshot service failed: HTTP {screenshot_response.status_code}")
            else:
                
                # Save zip file and extract it
                zip_path = os.path.join(screenshot_dir, f"{file_name}_screenshots.zip")
                with open(zip_path, 'wb') as zip_file:
                    zip_file.write(screenshot_response.content)
                
                # Extract zip file
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(screenshot_dir)
                os.remove(zip_path)  # Delete the zip file
                
                # The following code for displaying screenshots is commented out as it's Windows-specific
                # screenshot_files = sorted(
                #     [f for f in os.listdir(screenshot_dir) if f.lower().endswith('.png')],
                #     key=lambda x: "asm" in x  # Disassembly screenshots have priority
                # )
                # 
                # if not screenshot_files:
                #     logger.warning("No screenshot files found in the zip")
                # else:
                #     # Display screenshots one by one
                #     for screenshot_file in screenshot_files:
                #         screenshot_path = os.path.join(screenshot_dir, screenshot_file)
                #         with open(screenshot_path, 'rb') as img_file:
                #             self._show_screenshot(img_file.read())
                #         logger.info(f"Displayed screenshot: {screenshot_file}")
            
            # 2. Perform formal analysis (only upload filename)
            logger.info("[2/3], Starting formal analysis...")
            data = {
                'binary_name': file_name,
                'ida_version': ida_version.lower()
            }
            response = requests.post(bin_export_url, data=data, stream=True)

            # Check response status
            if response.status_code != 200:
                raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")
            # Save the result file
            output_file_path = os.path.join(output_dir, file_name + ".BinExport")
            with open(output_file_path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            logger.info(f"BinExport successfully! Results saved to: {output_file_path}")
            copy_file(output_file_path, os.path.join("test"))  # Copy the result file to the screenshots directory


            # 3. Export pseudo C code (only upload filename)
            logger.info("[3/3], Exporting pseudo C code...")
            response = requests.post(pseudo_c_url, data=data, stream=True)
            # Check response status
            if response.status_code != 200:
                raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")
                
           # 接收 BinExport idb的压缩文件
            bin_zip_path = os.path.join(output_dir, f"{file_name}_idao.zip")
            with open(bin_zip_path, 'wb') as bin_zip_file:
                for chunk in response.iter_content(1024):
                    bin_zip_file.write(chunk)
            
            # Extract zip file
            with zipfile.ZipFile(bin_zip_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
            os.remove(bin_zip_path)
            
            logger.info(f"Exported pseudo C code successfully! File saved to: {pseudo_c_file_path}")

            return True

        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}", exc_info=True)
            messagebox.showerror("Analysis Error", f"Analysis failed: {str(e)}")
            return False

    def get_tools(self) -> List[FunctionTool]:
        r"""Returns a list of FunctionTool objects representing the functions in the toolkit.

        Returns:
            List[FunctionTool]: A list of FunctionTool objects representing the functions in the toolkit.
        """
        return [
            FunctionTool(self.analyze_binary)
        ]

if __name__ == "__main__":
    # Example usage
    toolkit = IdaToolkit()
    toolkit.analyze_binary(r"/disk0/like/2025xa/owl/test/stack_overflow_demo_v1", output_dir=r"/disk0/like/2025xa/owl/test/20250514", ida_version="ida32",)

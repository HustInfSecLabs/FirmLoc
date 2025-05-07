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

logger = logging.getLogger(__name__)

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

    def analyze_binary(self, input_file_path: str, output_file_path: str = None, 
                   ida_version: str = "ida32",
                   url: str = "http://10.12.189.52:5000/analyze",
                   screenshot_url: str = "http://10.12.189.52:5000/analyze_with_screenshot") -> bool:
        r"""Analyze a binary file via HTTP API and save the result.

        Args:
            input_file_path (str): The path to the binary file to analyze.
            output_file_path (str, optional): The path to save the analysis result. 
                Defaults to None, in which case it will be saved as `<input_file_path>.BinExport`.
            ida_version (str, optional): The version of IDA to use ("ida32" or "ida64"). 
                Defaults to "ida32".
            url (str, optional): The HTTP API endpoint for analysis. 
                Defaults to "http://10.12.189.52:5000/analyze".
            screenshot_url (str, optional): The HTTP API endpoint for getting screenshot. 
                Defaults to "http://10.12.189.52:5000/analyze_with_screenshot".

        Returns:
            bool: True if the analysis was successful, False otherwise.
        """
        # Validate ida_version parameter
        if ida_version.lower() not in ["ida32", "ida64"]:
            raise ValueError(f"Invalid ida_version: {ida_version}. Must be 'ida32' or 'ida64'")

        # Set default output file path if not provided
        if output_file_path is None:
            output_file_path = f"{input_file_path}.BinExport"
        
        # Check if input file exists
        if not os.path.exists(input_file_path):
            raise FileNotFoundError(f"Input file does not exist: {input_file_path}")
        
        file_name = os.path.basename(input_file_path)
        file_dir = os.path.dirname(input_file_path)
        screenshots_dir = os.path.join(file_dir, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

        try:
            # 1. First send to screenshot service to get screenshots
            with open(input_file_path, 'rb') as f:
                files = {'file': (file_name, f)}
                logger.info(f"Sending file to screenshot service: {screenshot_url}")
                screenshot_response = requests.post(screenshot_url, files=files)
            
            if screenshot_response.status_code != 200:
                logger.warning(f"Screenshot service failed: HTTP {screenshot_response.status_code}")
            else:
                # Create temporary directory for extracted screenshots
                screenshot_dir = os.path.join(screenshots_dir, os.path.splitext(file_name)[0])
                os.makedirs(screenshot_dir, exist_ok=True)
                
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
            logger.info("Starting formal analysis...")
            data = {
                'binary_name': file_name,
                'ida_version': ida_version.lower()
            }
            response = requests.post(url, data=data, stream=True)

            # Check response status
            if response.status_code != 200:
                raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")

            # Save the result file
            with open(output_file_path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)

            logger.info(f"IDA analysis completed successfully! Results saved to: {output_file_path}")
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
    toolkit.analyze_binary(r"/disk0/like/2025xa/owl/test/stack_overflow_demo")

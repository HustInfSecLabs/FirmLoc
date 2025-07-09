import logging
import os
import zipfile
from typing import List
import requests

from camel.toolkits.base import BaseToolkit
from camel.toolkits.function_tool import FunctionTool
from utils.utils import is_binary_file

logger = logging.getLogger(__name__)

class IdaToolkit(BaseToolkit):
    r"""A class representing a toolkit for Ida binary analysis."""
    
    async def get_screenshots(self, input_file_path: str, output_dir: str, 
                        screenshot_url: str = "http://10.12.189.40:5000/reversing_analyze_screenshot") -> List[str]:
        r"""Get screenshots from the screenshot service.
        
        Args:
            input_file_path (str): Path to the binary file.
            output_dir (str): Directory to save screenshots.
            screenshot_url (str): URL of the screenshot service.
            
        Returns:
            list: List containing screenshot paths.
        """
        if not os.path.exists(input_file_path):
            logger.error(f"Input file does not exist: {input_file_path}")
            return []
        if not is_binary_file(input_file_path):
            logger.error(f"Input file is not a binary file: {input_file_path}")
            return []

        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(input_file_path), "screenshots")
        os.makedirs(output_dir, exist_ok=True)  # Ensure output directory exists
        file_name = os.path.basename(input_file_path)
        
        with open(input_file_path, 'rb') as f:
            files = {'file': (file_name, f)}
            logger.info(f"[1/3], Sending file to screenshot service: {screenshot_url}")
            screenshot_response = requests.post(screenshot_url, files=files)
        
        if screenshot_response.status_code != 200:
            logger.warning(f"Screenshot service failed: HTTP {screenshot_response.status_code}")
            return []
            
        # Save zip file and extract it
        zip_path = os.path.join(output_dir, f"{file_name}_screenshots.zip")
        with open(zip_path, 'wb') as zip_file:
            zip_file.write(screenshot_response.content)
        
        # Extract zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            file_names = zip_ref.namelist()
            screenshots_path = [
                os.path.join(output_dir, name) for name in file_names
            ]
            zip_ref.extractall(output_dir)
        os.remove(zip_path)  # Delete the zip file
        
        return screenshots_path
    
    async def get_binexport(self, input_file_path: str, output_dir: str, 
                        ida_version: str = "ida32", 
                        bin_export_url: str = "http://10.12.189.40:5000/export_binexport") -> List[str]:
        r"""Get BinExport and IDB files from the analysis service.
        
        Args:
            input_file_path (str): Path to the binary file.
            output_dir (str): Directory to save the output files.
            ida_version (str): IDA version ("ida32" or "ida64").
            bin_export_url (str): URL of the BinExport service.
            
        Returns:
            list: List containing BinExport and IDB file paths.
        """
        if not os.path.exists(input_file_path):
            logger.error(f"Input file does not exist: {input_file_path}")
            return []
        if not is_binary_file(input_file_path):
            logger.error(f"Input file is not a binary file: {input_file_path}")
            return []

        file_name = os.path.basename(input_file_path)
        if output_dir is None:
            output_dir = os.path.dirname(input_file_path)
        logger.info("[2/3], Starting export BinExport and idb...")
        data = {
            'binary_name': file_name,
            'ida_version': ida_version.lower()
        }
        response = requests.post(bin_export_url, data=data, stream=True)

        # Check response status
        if response.status_code != 200:
            raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")
        
        # Receive BinExport idb zip file
        bin_zip_path = os.path.join(output_dir, f"{file_name}_idao.zip")
        with open(bin_zip_path, 'wb') as bin_zip_file:
            for chunk in response.iter_content(1024):
                bin_zip_file.write(chunk)
        
        # Extract zip file
        with zipfile.ZipFile(bin_zip_path, 'r') as zip_ref:
            file_names = zip_ref.namelist()
            binexports_path = [
                os.path.join(output_dir, name) for name in file_names
            ]
            zip_ref.extractall(output_dir)
        os.remove(bin_zip_path)

        logger.info(f"BinExport and idb successfully!")
        return binexports_path

    async def get_pseudo_c(self, input_file_path: str, output_dir: str,
                        ida_version: str = "ida32",
                        pseudo_c_url: str = "http://10.12.189.40:5000/export_pseudo_c") -> str:
        r"""Get pseudo C code from the analysis service.
        
        Args:
            input_file_path (str): Path to the binary file.
            output_dir (str): Directory to save the output file.
            ida_version (str): IDA version ("ida32" or "ida64").
            pseudo_c_url (str): URL of the pseudo C service.
            
        Returns:
            str: Path to the pseudo C file.
        """
        if not os.path.exists(input_file_path):
            logger.error(f"Input file does not exist: {input_file_path}")
            return ""
        if not is_binary_file(input_file_path):
            logger.error(f"Input file is not a binary file: {input_file_path}")
            return ""
        
        file_name = os.path.basename(input_file_path)
        if output_dir is None:
            output_dir = os.path.dirname(input_file_path)
        logger.info("[3/3], Exporting pseudo C code...")
        data = {
            'binary_name': file_name,
            'ida_version': ida_version.lower()
        }
        response = requests.post(pseudo_c_url, data=data, stream=True)
        
        # Check response status
        if response.status_code != 200:
            raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")
        
        # Save the result file
        pseudo_c_file_path = os.path.join(output_dir, file_name + "_pseudo.c")
        with open(pseudo_c_file_path, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        logger.info(f"Exported pseudo C code successfully! File saved to: {pseudo_c_file_path}")
        return pseudo_c_file_path


    def get_tools(self) -> List[FunctionTool]:
        r"""Returns a list of FunctionTool objects representing the functions in the toolkit.

        Returns:
            List[FunctionTool]: A list of FunctionTool objects representing the functions in the toolkit.
        """
        return [
            FunctionTool(self.get_screenshots),
            FunctionTool(self.get_binexport),
            FunctionTool(self.get_pseudo_c)
        ]

if __name__ == "__main__":
    # Example usage
    toolkit = IdaToolkit()
    res = toolkit.get_screenshots(r"/disk0/like/2025xa/owl/test/ida_test/uhttpd26", output_dir=r"/disk0/like/2025xa/owl/test/ida_test")
    print(res)

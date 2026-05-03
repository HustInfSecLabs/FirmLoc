import logging
import os
import zipfile
import asyncio
from typing import List
import requests
from requests_toolbelt import MultipartEncoder

from camel.toolkits.base import BaseToolkit
from camel.toolkits.function_tool import FunctionTool
from utils.utils import is_binary_file

logger = logging.getLogger(__name__)

class IdaToolkit(BaseToolkit):
    r"""A class representing a toolkit for Ida binary analysis."""

    async def get_screenshots(self, input_file_path: str, output_dir: str, ida_version: str = "ida32",
                        screenshot_url: str = "http://localhost:5000/reversing_analyze_screenshot") -> List[str]:
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
        os.makedirs(output_dir, exist_ok=True)
        file_name = os.path.basename(input_file_path)

        def _request_and_extract() -> List[str]:
            with open(input_file_path, 'rb') as f:
                files = {'file': (file_name, f)}
                logger.info(f"[1/3], Sending file to screenshot service: {screenshot_url}")
                screenshot_response = requests.post(
                    screenshot_url,
                    files=files,
                    data={'ida_version': ida_version.lower()},
                )

            if screenshot_response.status_code != 200:
                logger.warning(f"Screenshot service failed: HTTP {screenshot_response.status_code}")
                return []

            zip_path = os.path.join(output_dir, f"{file_name}_screenshots.zip")
            with open(zip_path, 'wb') as zip_file:
                zip_file.write(screenshot_response.content)

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_names = zip_ref.namelist()
                screenshots_path = [os.path.join(output_dir, name) for name in file_names]
                zip_ref.extractall(output_dir)
            os.remove(zip_path)
            return screenshots_path

        return await asyncio.to_thread(_request_and_extract)

    async def get_binexport(self, input_file_path: str, output_dir: str,
                        ida_version: str = "ida32",
                        bin_export_url: str = "http://localhost:5000/export_binexport") -> List[str]:
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

        def _request_and_extract() -> List[str]:
            data = {
                'binary_name': file_name,
                'binary_path': input_file_path,
                'ida_version': ida_version.lower()
            }
            response = requests.post(bin_export_url, data=data, stream=True)

            if response.status_code != 200:
                raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")

            bin_zip_path = os.path.join(output_dir, f"{file_name}_idao.zip")
            with open(bin_zip_path, 'wb') as bin_zip_file:
                for chunk in response.iter_content(1024):
                    bin_zip_file.write(chunk)

            with zipfile.ZipFile(bin_zip_path, 'r') as zip_ref:
                file_names = zip_ref.namelist()
                binexports_path = [os.path.join(output_dir, name) for name in file_names]
                zip_ref.extractall(output_dir)
            os.remove(bin_zip_path)
            logger.info("BinExport and idb successfully!")
            return binexports_path

        return await asyncio.to_thread(_request_and_extract)

    async def get_pseudo_c(self, input_file_path: str, output_dir: str,
                        ida_version: str = "ida32",
                        pseudo_c_url: str = "http://localhost:5000/export_pseudo_c") -> str:
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

        def _request_and_write() -> str:
            data = {
                'binary_name': file_name,
                'binary_path': input_file_path,
                'ida_version': ida_version.lower()
            }
            response = requests.post(pseudo_c_url, data=data, stream=True)

            if response.status_code != 200:
                raise RuntimeError(f"Analysis failed: HTTP {response.status_code} - {response.text}")

            pseudo_c_file_path = os.path.join(output_dir, file_name + "_pseudo.c")
            with open(pseudo_c_file_path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            logger.info(f"Exported pseudo C code successfully! File saved to: {pseudo_c_file_path}")
            return pseudo_c_file_path

        return await asyncio.to_thread(_request_and_write)


    async def extract_strings(self, input_file_path: str, ida_version: str = "ida32",
                        string_url: str = "http://localhost:5000/export_strings") -> dict:
        """Export hardcoded strings from a binary via IDA service.

        Args:
            input_file_path: Path to the binary.
            ida_version: "ida32" or "ida64".
            string_url: IDA service endpoint for string extraction.

        Returns:
            dict: JSON payload returned by the service, or {} on failure.
        """
        if not os.path.exists(input_file_path):
            logger.error(f"Input file does not exist: {input_file_path}")
            return {}
        if not is_binary_file(input_file_path):
            logger.error(f"Input file is not a binary file: {input_file_path}")
            return {}

        file_name = os.path.basename(input_file_path)

        def _send_request():
            with open(input_file_path, 'rb') as f:
                m = MultipartEncoder(
                    fields={
                        'file': (file_name, f, 'application/octet-stream'),
                        'ida_version': ida_version.lower()
                    }
                )
                logger.info(f"Sending file to string extraction service: {string_url}")
                return requests.post(
                    string_url,
                    data=m,
                    headers={'Content-Type': m.content_type},
                    timeout=3600
                )

        try:
            response = await asyncio.to_thread(_send_request)
        except Exception as e:
            logger.error(f"String extraction request failed: {e}")
            return {}

        if response.status_code != 200:
            logger.error(f"String extraction service failed: HTTP {response.status_code}")
            return {}

        try:
            return response.json()
        except Exception as e:
            logger.error(f"Failed to parse string extraction response: {e}")
            return {}


    async def get_string_context(self, binary_path: str, strings: list, max_xrefs: int = 10,
                            context_url: str = "http://localhost:5000/string_context") -> dict:
        """获取可疑字符串的代码上下文（交叉引用分析）

        通过IDA分析字符串在二进制中的使用位置，获取反编译后的函数代码作为上下文。
        """
        if not strings:
            logger.warning("No strings provided for context analysis")
            return {"status": "error", "message": "No strings provided"}

        import os as _os
        binary_name = _os.path.basename(binary_path)
        request_data = {
            "binary_path": binary_path,
            "binary_name": binary_name,
            "strings": strings,
            "max_xrefs": max_xrefs
        }

        def _send_request():
            logger.info(f"Sending string context request: {len(strings)} strings for {binary_name} to {context_url}")
            return requests.post(
                context_url,
                json=request_data,
                timeout=3600
            )

        try:
            response = await asyncio.to_thread(_send_request)
        except requests.exceptions.Timeout:
            logger.error("String context request timed out")
            return {"status": "error", "message": "Request timed out"}
        except Exception as e:
            logger.error(f"String context request failed: {e}")
            return {"status": "error", "message": str(e)}

        if response.status_code != 200:
            logger.error(f"String context service failed: HTTP {response.status_code}")
            try:
                error_msg = response.json().get("message", response.text)
            except Exception:
                error_msg = response.text
            return {"status": "error", "message": error_msg, "http_status": response.status_code}

        try:
            return response.json()
        except Exception as e:
            logger.error(f"Failed to parse string context response: {e}")
            return {"status": "error", "message": f"Failed to parse response: {e}"}


    def get_tools(self) -> List[FunctionTool]:
        r"""Returns a list of FunctionTool objects representing the functions in the toolkit.

        Returns:
            List[FunctionTool]: A list of FunctionTool objects representing the functions in the toolkit.
        """
        return [
            FunctionTool(self.get_screenshots),
            FunctionTool(self.get_binexport),
            FunctionTool(self.get_pseudo_c),
            FunctionTool(self.extract_strings),
            FunctionTool(self.get_string_context)
        ]

if __name__ == "__main__":
    toolkit = IdaToolkit()
    res = toolkit.get_screenshots(r"/disk0/like/2025xa/owl/test/ida_test/uhttpd26", output_dir=r"/disk0/like/2025xa/owl/test/ida_test")
    print(res)

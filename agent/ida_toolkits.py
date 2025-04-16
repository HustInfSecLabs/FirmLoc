import logging
import os
from typing import List
import requests

from camel.toolkits.base import BaseToolkit
from camel.toolkits.function_tool import FunctionTool

logger = logging.getLogger(__name__)


class IdaToolkit(BaseToolkit):
    r"""A class representing a toolkit for Ida binary analysis."""

    def analyze_binary(self, input_file_path: str, output_file_path: str = None, url: str = "http://10.12.189.52:5000/analyze") -> bool:
        r"""Analyze a binary file via HTTP API and save the result.

        Args:
            input_file_path (str): The path to the binary file to analyze.
            output_file_path (str, optional): The path to save the analysis result. Defaults to None, in which case it will be saved as
                `<input_file_path>_test.export`.
            url (str, optional): The HTTP API endpoint for analysis. Defaults to "http://10.12.189.52:5000/analyze".

        Returns:
            bool: True if the analysis was successful, False otherwise.
        """
        # Set default output file path if not provided
        if output_file_path is None:
            output_file_path = f"{input_file_path}.export"
        
        # Check if input file exists
        if not os.path.exists(input_file_path):
            raise FileNotFoundError(f"Input file does not exist: {input_file_path}")
        
        file_name = os.path.basename(input_file_path)

        try:
            # Send the file via HTTP POST request
            with open(input_file_path, 'rb') as f:
                files = {'file': (file_name, f)}
                response = requests.post(url, files=files, stream=True)

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
            logger.error(f"Error during analysis: {str(e)}")
            return False

    def get_tools(self) -> List[FunctionTool]:
        r"""Returns a list of FunctionTool objects representing the functions in the toolkit.

        Returns:
            List[FunctionTool]: A list of FunctionTool objects representing the functions in the toolkit.
        """
        return [
            FunctionTool(self.analyze_binary)
        ]

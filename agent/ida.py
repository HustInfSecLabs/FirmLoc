
from agent.ida_toolkits import IdaToolkit
from utils import ConfigManager
from utils.utils import copy_file, rename_file_with_b64_timestamp
import asyncio
import os

async def ida_process(input_file_path: str, output_dir: str = None,
        ida_service_url: str = "http://localhost:5000",
        ida_version: str = "ida32",
        config: ConfigManager = None,
        send_message=None,
        on_status_update=None) -> dict:
    """
    Analyze a binary file using IDA and return the results.
    Args:
        input_file_path (str): The path to the binary file to analyze.
        output_dir (str, optional): The directory to save the analysis results. Defaults to None.
        ida_version (str, optional): The version of IDA to use ("ida32" or "ida64"). Defaults to "ida32".
        config (ConfigManager, optional): Configuration manager instance. Defaults to None.
        send_message (function, optional): Function to send messages. Defaults to None.
        on_status_update (function, optional): Function to update status. Defaults to None.
    Returns:
        dict: A dictionary containing the results of the analysis, including paths to screenshots, BinExport, and pseudo C code.
    """
    agent = "IDA Agent"
    tool = "IDA Decompiler"
    tool_status = "running"
    tool_type = "graphics"
    IDAAgent = IdaToolkit()

    # 更新状态
    config.update_tool_status("Binwalk", "IDA Decompiler")
    if on_status_update:
        on_status_update(None, tool, tool_status)
    result_list = await IDAAgent.get_screenshots(input_file_path ,os.path.join(output_dir, "screenshots") if output_dir else None, ida_version=ida_version, screenshot_url=ida_service_url + "/reversing_analyze_screenshot")
    # result_dict = {
    #     "screenshots": ["12343.png", "12344.png"],
    #     "binexport": ["binfilename.BinExport", "binfilename.idb"],
    #     "pseudo_c": "binfilename_pseudo.c",
    #     "state": True,
    #     "error": None
    # }
    screenshots = []
    for screenshot in result_list:
        file = copy_file(screenshot, "images")
        rename_file = os.path.join("/static", rename_file_with_b64_timestamp(file))
        screenshots.append(rename_file)

    filename = input_file_path.split("./", 1)[-1]    
    tool_content = [
        {
            "type": "text",
            "content": f"IDA反编译文件{filename}",

        }
    ] + [

        {"type": "picture", "link": screenshot} for screenshot in screenshots
    ]
    if send_message:
        await send_message(
            f"正在执行: IDA反编译文件{filename}",
            "message",
            tool_type,
            tool_content,
            agent=agent,
            tool=tool,
            tool_status=tool_status
        )
        await asyncio.sleep(1)

    files = await IDAAgent.get_binexport(input_file_path, output_dir, ida_version=ida_version, bin_export_url=ida_service_url + "/export_binexport")

     # 复制binexport文件到test目录
    copy_file(os.path.join(output_dir, os.path.basename(input_file_path) + ".BinExport"), os.path.join("test"))

    c_file = await IDAAgent.get_pseudo_c(input_file_path, output_dir, ida_version=ida_version, pseudo_c_url=ida_service_url + "/export_pseudo_c")

    return files
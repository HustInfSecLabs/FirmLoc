import subprocess
import time
import os

CLICK_BUTTONS = {
    "left_click": "1",
    "middle_click": "2",
    "right_click": "3",
    "double_click": ["--repeat", "2", "--delay", "10", "1"],
}

HOME = "/home/username"  # 截图保存的路径, 请根据需要修改 username
DIFF_FILE = "/path/to/stack_overflow_demo.export"  # 请替换为实际的文件路径
IMAGE_DIR = "/image/"
IMAGE_FILE = [
    "overview_screenshot.png",
    "call_graph_screenshot.png",
    "matched_functions_screenshot.png",
    "primary_unmatched_functions_screenshot.png",
    "secondary_unmatched_functions_screenshot.png",
]

# 坐标和延迟时间配置
COORDINATES = {
    "file_menu": (90, 411),
    "diff_menu": (788, 533),
    "default_file": (227, 534),
    "confirm_ok": (615, 771),
    "rename_field": (795, 665),
    "confirm_add": (686, 708),
    "select_diff": (103, 378),
    "overview_tab": (99, 392),
    "call_graph_tab": (99, 412),
    "matched_functions_tab": (99, 426),
    "primary_unmatched_tab": (99, 443),
}

DELAY_SHORT = 0.5
DELAY_LONG = 1


def bindiff_ui(diff_name: str, output_image: str):
    """运行 BinDiff GUI 工具加载对比文件并截图"""
    try:
        # 启动 BinDiff
        subprocess.Popen(["bindiff", "-ui"])
        time.sleep(3)  # 等待 BinDiff 启动

        active_bindiff()

        # 打开文件菜单并加载对比文件
        open_file_menu()
        load_diff_file(diff_name)

        # 截图各个视图
        take_screenshots(output_image)
    except Exception as e:
        print(f"运行 BinDiff 时发生错误: {e}")


def open_file_menu():
    """打开文件菜单"""
    subprocess.run(["xdotool", "key", "Alt+f"])
    time.sleep(DELAY_SHORT)
    move_and_click(*COORDINATES["file_menu"], "left_click")
    time.sleep(DELAY_LONG)


def load_diff_file(diff_name: str):
    """加载对比文件"""
    subprocess.run(["xdotool", "key", "Alt+d"])
    time.sleep(DELAY_LONG)
    subprocess.run(["xdotool", "key", "Ctrl+a"])
    time.sleep(DELAY_LONG)

    move_and_click(*COORDINATES["diff_menu"], "left_click")
    time.sleep(DELAY_LONG)
    move_and_click(*COORDINATES["default_file"], "left_click")
    time.sleep(DELAY_LONG)
    move_and_click(*COORDINATES["confirm_ok"], "left_click")
    time.sleep(DELAY_SHORT)

    move_and_click(*COORDINATES["rename_field"], "left_click")
    clear_and_type(diff_name)
    move_and_click(*COORDINATES["confirm_add"], "left_click")
    time.sleep(DELAY_SHORT)

    move_and_click(*COORDINATES["select_diff"], "double_click")
    time.sleep(DELAY_LONG)


def take_screenshots(output_image: str):
    """截图各个视图"""
    tabs = [
        "overview_tab",
        "call_graph_tab",
        "matched_functions_tab",
        "primary_unmatched_tab",
        "secondary_unmatched_tab",
    ]

    for i, tab in enumerate(tabs):
        active_bindiff()
        time.sleep(DELAY_LONG)
        move_and_click(*COORDINATES[tab], "left_click")
        time.sleep(DELAY_LONG)
        screenshot_path = os.path.join(output_image, IMAGE_FILE[i])
        subprocess.run(["scrot", "-u", screenshot_path])
        time.sleep(DELAY_LONG)


def move_and_click(x, y, mode):
    """移动鼠标到指定位置并点击"""
    try:
        action_mode = CLICK_BUTTONS.get(mode, "1")
        subprocess.run(["xdotool", "mousemove", str(x), str(y), "click", *action_mode])
    except Exception as e:
        print(f"鼠标操作失败: {e}")


def clear_and_type(input_text):
    """清空输入框并输入文本"""
    try:
        subprocess.run(["xdotool", "key", "Ctrl+a"])
        time.sleep(DELAY_SHORT)
        subprocess.run(["xdotool", "key", "BackSpace"])
        time.sleep(DELAY_SHORT)
        subprocess.run(["xdotool", "type", input_text])
    except Exception as e:
        print(f"输入文本失败: {e}")


def active_bindiff():
    """激活 BinDiff 窗口"""
    try:
        subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "BinDiff", "windowactivate"])
    except Exception as e:
        print(f"激活 BinDiff 窗口失败: {e}")


if __name__ == "__main__":
    # 示例用法
    bindiff_ui(HOME + IMAGE_DIR, "test_diff_name")
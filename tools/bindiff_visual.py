import subprocess
import time
import os

CLICK_BUTTONS = {
    "left_click": "1",
    "middle_click": "2",
    "right_click": "3",
    "double_click": ["--repeat", "2", "--delay", "10", "1"],
}

HOME = "/home/wzh/Desktop/Project/VulnAgent/"  # 截图保存的路径, 请根据需要修改 username
DIFF_FILE = "~/Desktop/Project/VulnAgent/test/"              
# "/path/to/stack_overflow_demo.export"  # 请替换为实际的文件路径
IMAGE_DIR = "/images/"
IMAGE_FILE = [
    "overview_screenshot.png",
    "call_graph_screenshot.png",
    "matched_functions_screenshot.png",
    "primary_unmatched_functions_screenshot.png",
    "secondary_unmatched_functions_screenshot.png",
]

ANCHOR = {
    "PATH": (1671, 787),
    "ICON": (155, 214),
    "SEARCH_BOX1": (522, 425),  # Matched Functions
    "SEARCH_BOX2": (),  # Primary/Secondary Unmatched Functions
    "MATCHED_FUNCTIONS": (368, 414), # Interval is 21, such as 408 -> 429
    "SEARCH_BOX3": (1065, 141), # Node Content
}

# 坐标和延迟时间配置
COORDINATES = {
    "workplace": (178, 241),
    "diff_menu": ANCHOR["PATH"],
    # "default_file": (ANCHOR["PATH"][0] - 560, ANCHOR["PATH"][1]),
    "default_file": (1133, 775),
    # "confirm_ok": (ANCHOR["PATH"][0] - 171, ANCHOR["PATH"][1] + 242),
    "confirm_ok": (1492, 1015),
    # "rename_field": (ANCHOR["PATH"][0] - 14, ANCHOR["PATH"][1] + 135),
    "rename_field": (1151, 927),
    # "confirm_add": (ANCHOR["PATH"][0] - 100, ANCHOR["PATH"][1] + 174),
    "confirm_add": (1559, 965),
    "overview_tab": ANCHOR["ICON"],
    "call_graph_tab": (ANCHOR["ICON"][0] + 20, ANCHOR["ICON"][1] + 17),
    "matched_functions_tab": (ANCHOR["ICON"][0] + 20, ANCHOR["ICON"][1] + 34),
    "primary_unmatched_tab": (ANCHOR["ICON"][0] + 20, ANCHOR["ICON"][1] + 51),
    "secondary_unmatched_tab": (ANCHOR["ICON"][0] + 20, ANCHOR["ICON"][1] + 68),
    "delete_diff": (ANCHOR["ICON"][0] + 14, ANCHOR["ICON"][1] + 57),
    "delete_file_select": (ANCHOR["PATH"][0] - 454, ANCHOR["PATH"][1] + 85),
    "confirm_delete":(ANCHOR["PATH"][0] - 354, ANCHOR["PATH"][1] + 120),
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
        open_workplace()
        load_diff_file(diff_name)

        # 截图各个视图
        screenshots =  take_screenshots(output_image)
        
        delete_diff_file(DIFF_FILE)
        # Exit BinDiff
        close_bindiff()
        return screenshots
    except Exception as e:
        print(f"运行 BinDiff 时发生错误: {e}")
        return []


def open_workplace():
    """打开文件菜单"""
    subprocess.run(["xdotool", "key", "Alt+f"])
    time.sleep(DELAY_SHORT)
    move_and_click(*COORDINATES["workplace"], "left_click")
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

    move_and_click(*COORDINATES["overview_tab"], "double_click")
    time.sleep(DELAY_LONG)


def delete_diff_file(diff_dir: str):
    """Delete diff file"""
    move_and_click(*ANCHOR["ICON"], "right_click")
    time.sleep(DELAY_SHORT)
    move_and_click(*COORDINATES["delete_diff"], "left_click")
    time.sleep(DELAY_SHORT)
    # Actually it does not work.
    move_and_click(*COORDINATES["delete_file_select"], "left_click")
    move_and_click(*COORDINATES["confirm_delete"], "left_click")
    # It does work.
    subprocess.run(["rm", "-rf", diff_dir])
    
    
def take_screenshots(output_image: str):
    """截图各个视图"""
    tabs = [
        "overview_tab",
        "call_graph_tab",
        "matched_functions_tab",
        "primary_unmatched_tab",
        "secondary_unmatched_tab",
    ]
    screenshots = []
    for i, tab in enumerate(tabs):
        os.makedirs(output_image, exist_ok=True)
        active_bindiff()
        time.sleep(DELAY_LONG)
        move_and_click(*COORDINATES[tab], "left_click")
        time.sleep(DELAY_LONG)
        screenshot_path = os.path.join(output_image, IMAGE_FILE[i])
        screenshots.append(screenshot_path)
        subprocess.run(["scrot", "-u", screenshot_path])
        time.sleep(DELAY_LONG)

    return screenshots

def scrot(path: str):
    try:
        subprocess.run(["scrot", "-u", path])
    except Exception as e:
        print(f"scrot操作失败: {e}")

def find_matched_function(name: str):
    """在已匹配的函数中寻找给定函数"""
    move_and_click(*ANCHOR["SEARCH_BOX1"], "left_click")
    clear_and_type(name)
    time.sleep(DELAY_LONG)
    move_and_click(*ANCHOR["MATCHED_FUNCTIONS"], "double_click") # Default First
    time.sleep(DELAY_LONG)
    hightlight_nodes("push")
    
    
def hightlight_nodes(node_content: str):
    """Hightlight the search content of Graph node """
    move_and_click(*ANCHOR["SEARCH_BOX3"], "left_click")
    clear_and_type(node_content)
    time.sleep(DELAY_SHORT)
    scrot(HOME + IMAGE_DIR+"diff_function"+node_content+".png")
    
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
        time.sleep(DELAY_SHORT)
        subprocess.run(["xdotool", "key", "Return"]) # Enter or Return
    except Exception as e:
        print(f"输入文本失败: {e}")


def active_bindiff():
    """激活 BinDiff 窗口"""
    try:
        subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "BinDiff", "windowactivate"])
    except Exception as e:
        print(f"激活 BinDiff 窗口失败: {e}")


def close_bindiff():
    """Close Bindiff UI"""
    subprocess.run(["xdotool", "key", "Alt+f"])
    time.sleep(DELAY_SHORT)
    subprocess.run(["xdotool", "key", "Ctrl+q"])
    
if __name__ == "__main__":
    # 示例用法
    bindiff_ui("test_diff_name0514", HOME + IMAGE_DIR)
    # find_matched_function("main")
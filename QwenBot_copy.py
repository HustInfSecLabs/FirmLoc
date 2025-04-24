from dotenv import dotenv_values
config = dotenv_values('.qwenenv')
from openai import OpenAI
import json
import os
import logging


# 配置日志记录
logging.basicConfig(
    filename='shell_test.log',  # 日志文件名
    level=logging.INFO,      # 日志级别
    format='%(asctime)s - %(levelname)s - %(message)s',  # 日志格式
    datefmt='%Y-%m-%d %H:%M:%S',  # 日期时间格式
    filemode='w'  # 使用 'w' 模式覆盖旧日志，使用 'a' 模式追加到现有日志    
)


# 创建一个日志记录器
logger = logging.getLogger()
class QwenBot:
    def send_message(self, content):
        client = OpenAI(
            # api_key="sk-96dfbe8884db412389097aba133fd2", # deepseek
            # base_url="https://api.deepseek.com", 
            api_key="", # 请在此处用您的API Key进行替换sk-96dfbe8884db412389097aba133fd2
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # 填写DashScope服务的base_url
        )

        completion = client.chat.completions.create(
            model="qwen-plus", 
            # model="deepseek-coder",   
            messages=[
                {'role': 'system', 'content': 'You are a helpful assistant.'},
                {'role': 'user', 'content': content}],
            temperature=0.2,
            top_p=0.8
            )
        result = completion.model_dump_json()
        result_dict = json.loads(result)
        # print("QwenBot result:", result)
        logging.info(f"QwenBot response: {json.dumps(result_dict, ensure_ascii=False, indent=4)}")
        # decoded_output = result.encode('utf-8').decode('unicode_escape')
        # print("decoded_output:", decoded_output)
        return json.loads(result)


    def multi_round_test(self):
        while True:
            input_value = input("请输入问题（输入'quit'退出）: ")
            if input_value == 'quit':
                break
            else:
                
                self.send_message(input_value)


if __name__ == '__main__':
    bot = QwenBot()
    bot.multi_round_test()
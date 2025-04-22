from QwenBot import QwenBot
import os
import re
import shutil
import logging
# from dotenv import dotenv_values
# config = dotenv_values('.wenxinenv')
PROMPT = """你是一个代码漏洞分析专家，用户会给你两个文件，分别是[fileA]和[fileB]，以及一个固定的函数集[funcs]，
[fileA]和[fileB]是一对相似的函数文件,[funcs]是两个文件包含的函数集合。

你的任务是根据输入的[fileA]和[fileB]，仔细分析两个文件不同的地方，进而判断两段代码片段中是否包含潜在的漏洞，并使用中文进行输出[result],
你输出的[result]应该包含如下内容：
首先说明[fileA]以及[fileB]的文件名。
判断两段代码中是否包含漏洞，如果两段代码片段都不包含漏洞，则不需要输出其他信息，只需要输出"NULL"。
如果包含漏洞则需要输出以下具体的信息：
首先说明漏洞的所属类型以及漏洞的产生原因
其次说明漏洞所在是在[fileA]和[fileB]
最后说明漏洞所在的位置，说明漏洞的所在行号以及代码内容。

最后对你的所有的输出进行一个统计，统计各个类型漏洞的数量。

以下为真实应用场景:
[funcs]
    "printf","gets", "scanf",
    "alloca", "malloc", "calloc","realloc",
    "memmove", "memcpy", "strcpy", "strncpy", "stpcpy", "wcscpy", "wcpcpy", 
    "stpncpy", "strlcpy", "strscpy","wcsncpy", "wcpncpy","wcslcpy", 
    "strcat", "strncat","strlcat","wcscat","wcslcat",
    "fopen", "fread", "fwrite", "fclose","read",
    "system", "send", "recv", 
    "sizeof",  "strlen","memset","wmemset","bcopy"
[funcs end]

[filea]
{$filea$}
[filea end]

[fileb]
{$fileb$}
[fileb end]


[result]
{$result$}
[result end]

"""
class refiner:
    def __init__(self) -> None:
        self.bot = QwenBot()
        self.prompt_template = PROMPT

    def make_prompt(self, filea, fileb):
        prompt = self.prompt_template.replace("{$filea$}", filea).replace("{$fileb$}", fileb)
        return prompt

    def split_file_content(self, content, max_lines=1200):
        lines = content.splitlines(True)
        for i in range(0, len(lines), max_lines):
            yield ''.join(lines[i:i + max_lines])

    def add_filename_to_batch(self, filename, batch_content):
        """添加文件名到批次内容前"""
        return f"File: {filename}\n{batch_content}"

    def query2bot(self, file_path_a, file_path_b):
        # Read the contents of the files
        with open(file_path_a, 'r', encoding='utf-8') as fa, open(file_path_b, 'r', encoding='utf-8') as fb:
            content_a = fa.read()
            content_b = fb.read()

        # Split the content into batches if necessary
        batched_content_a = list(self.split_file_content(content_a))
        batched_content_b = list(self.split_file_content(content_b))

        responses = []
        file_name_a = os.path.basename(file_path_a)
        file_name_b = os.path.basename(file_path_b)

        for batch_a, batch_b in zip(batched_content_a, batched_content_b):
            # Add filenames to each batch
            batch_a_with_name = self.add_filename_to_batch(file_name_a, batch_a)
            batch_b_with_name = self.add_filename_to_batch(file_name_b, batch_b)

            query = self.make_prompt(batch_a_with_name, batch_b_with_name)
            response = self.bot.send_message(query)
            responses.append(response)

            with open("refiner.txt", "a", encoding='utf-8') as f:
                f.write(query + '\n')  # Adding a newline for better readability in log

        # Handle the case where one file has more batches than the other
        longer_batch_list = batched_content_a if len(batched_content_a) > len(batched_content_b) else batched_content_b
        shorter_batch_list = batched_content_b if len(batched_content_a) > len(batched_content_b) else batched_content_a
        longer_file_name = file_name_a if len(batched_content_a) > len(batched_content_b) else file_name_b

        for extra_batch in longer_batch_list[len(shorter_batch_list):]:
            # Add filename to the extra batch
            extra_batch_with_name = self.add_filename_to_batch(longer_file_name, extra_batch)

            query = self.make_prompt(extra_batch_with_name, '') if len(batched_content_a) > len(batched_content_b) else self.make_prompt('', extra_batch_with_name)
            response = self.bot.send_message(query)
            responses.append(response)

            with open("refiner.txt", "a", encoding='utf-8') as f:
                f.write(query + '\n')

        return responses

    
def find_files_in_folder(folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            yield os.path.join(root, file)

pattern = re.compile(r'(?P<address1>[0-9A-F]{8})\s*(?P<address2>[0-9A-F]{8})\s*(?P<similarity>0|1|0\.[0-9]+|1\.0)\s*.*?"(?P<function1>[^"]+)"\s*"(?P<function2>[^"]+)"')

def main():
    folder_a = 'E:/LLM-diff/funcs-12.01a/test3'
    folder_b = 'E:/LLM-diff/funcs-12.02a/sen_funs_not_1'
    func_result_file = 'E:/LLM-diff/func_result.txt'
    
    refiner_instance = refiner()
    for file_a in find_files_in_folder(folder_a):
        with open(func_result_file, 'r') as file:
            filea_name = os.path.basename(file_a)  # 提取文件名
            for line in file:
                match = pattern.search(line)
                if filea_name in line:  # 假设line格式为: filea "fileb" "filec"
                    function1, function2 = match.group('function1'), match.group('function2')
                    fileb = function2
                    file_b_path = os.path.join(folder_b, fileb)
                    if os.path.exists(file_b_path):
                        refiner_instance.query2bot(file_a, file_b_path)

if __name__ == '__main__':
    main()
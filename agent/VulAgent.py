import asyncio
import os
import re
from fastapi import WebSocket
from pathlib import Path
from typing import Set

from model import ChatModel, QwenChatModel, AgentModel
from agent import UserAgent, PlannerAgent
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from agent.ida_toolkits import IdaToolkit
from agent.binwalk import BinwalkAgent
from agent.online_search import OnlineSearchAgent
from agent.llm_diff import Refiner
from agent.binary_filter import BinaryFilterAgent
from log import logger
from utils import ConfigManager, PlanManager
from utils.utils import get_firmware_files




PROMPT ="""你是一个安全分析师，现在在进行漏洞复现，下面是Netgear R9000 设备的固件文件以及对应的CVE的相关信息，请分析哪个二进制文件可能有漏洞，下面是固件的usr/sbin目录 

[directory]
├── 11ad_fw_log_capture.sh
├── 80211stats
├── aclctl
├── acld
├── aclhijackdns
├── acl_update_name
├── afpd
├── afppasswd
├── am_listen
├── api -> ntgr_sw_api
├── app-register -> ntgr_sw_api
├── apstats
├── assocdenialnotify
├── atd
├── athadhoc
├── athdiag
├── athstats
├── athstatsclr
├── athtestcmd
├── avahi-autoipd
├── avahi-daemon
├── avahi-dnsconfd
├── bc
├── blkid
├── bond-ctrl
├── bond-monitor
├── bond-set
├── bond-show
├── boxlogin
├── brctl
├── build-ca
├── build-dh
├── build-inter
├── build-key
├── build-key-pass
├── build-key-pkcs12
├── build-key-server
├── build-req
├── build-req-pass
├── check_lang
├── check_time_machine
├── chroot -> ../../bin/busybox
├── clean-all
├── cmd_cron
├── cnid_dbd
├── cnid_metad
├── crond -> ../../bin/busybox
├── dbus-daemon
├── detach_afp_shares
├── detectSATA
├── detwan
├── dev-scan
├── dhcp6c
├── dhcp6ctl
├── dhcp6s
├── disktype
├── dlclient
├── dlna -> ntgr_sw_api
├── dns-hijack
├── dnsmasq
├── dsyslog
├── e2fsck
├── ebtables
├── eeprog
├── emule_firewall
├── ethtool
├── ez-ipupdate
├── file_notify
├── firewall -> ntgr_sw_api
├── flash_erase
├── forked-daapd
├── ftpload -> /dev/null
├── ftptop
├── getpcode
├── get_plex_pcode
├── greendownload
├── green_download.sh
├── green_download_upgrade.sh
├── hash-data
├── hostapd
├── hostapd_cli
├── icqm
├── inetd
├── inherit-inter
├── inotifywait
├── inotifywatch
├── internet -> ntgr_sw_api
├── ip
├── ip6tables -> xtables-multi
├── ip6tables-restore -> xtables-multi
├── ip6tables-save -> xtables-multi
├── ipp
├── iptables -> xtables-multi
├── iptables-restore -> xtables-multi
├── iptables-save -> xtables-multi
├── itunes_allow_control
├── iw
├── iwconfig
├── iwgetid -> iwconfig
├── iwlist -> iwconfig
├── iwpriv -> iwconfig
├── iwspy -> iwconfig
├── jq
├── lacp-debug
├── lbd
├── lbt
├── list-crl
├── lld2d
├── lspci
├── minidlna
├── miniupnpd
├── mke2fs
├── mkfs.ext2 -> mke2fs
├── mkfs.ext3 -> mke2fs
├── mkfs.ext4 -> mke2fs
├── mount.cifs
├── mtdinfo
├── nanddump
├── nandtest
├── nandwrite
├── net-cgi
├── netconn
├── netconn.sh
├── netdrive
├── netdrive.sh
├── net-scan
├── net-wall
├── nmbd -> samba_multicall
├── noip2
├── ntgrddns
├── ntgr_sw_api
├── ntgr_sw_api_event_notify
├── ntpclient
├── ntpclient-qos
├── ntpst
├── nusb_right.sh
├── nvconfig -> ntgr_sw_api
├── openvpn
├── parted
├── partprobe
├── phddns
├── pkitool
├── pktlogconf
├── pktlogdump
├── plex_net_dev
├── potd
├── potval
├── pppd
├── ppp-nas
├── proftpd
├── px5g
├── Qcmbr
├── ra_check
├── radardetect
├── radardetect_cli
├── radartool
├── radvd
├── radvdump
├── rdate -> ../../bin/busybox
├── readycloud_unregister
├── remote_fsize
├── remote_share_conf
├── remote_smb_conf
├── remote_user_conf
├── repacd-run.sh
├── revoke-full
├── ripd
├── ripngd
├── samba_multicall
├── save_shadow
├── select_partition
├── send_wol
├── setpci
├── sign-req
├── smbclient
├── smbd -> samba_multicall
├── smbpasswd -> samba_multicall
├── spectraltool
├── ssdk_sh
├── ssidsteering
├── ssmtp
├── stamac
├── system -> ntgr_sw_api
├── taskset
├── tc
├── tcpdump
├── telnetenable
├── thermaltool
├── tx99tool
├── ubiattach
├── ubidetach
├── ubimkvol
├── ubinfo
├── ubinize
├── uhttpd
├── update_afp
├── update-pciids
├── update_smb
├── update_user
├── usb_cfg
├── utelnetd
├── vmstat
├── vol_id
├── wget
├── wget_netgear
├── whichopensslcnf
├── wifitool
├── wifi_try
├── wigig_logcollector
├── wigig_remoteserver
├── wlanconfig
├── wol
├── wpa_supplicant
├── wps_enhc
├── xtables-multi
└── zebra
[/directory]

[CVE details]
CVE-2019-20760
描述信息
NETGEAR R9000 devices before 1.0.4.26 are affected by authentication bypass.
[/CVE details]
"""

# 调用大模型分析哪个二进制文件可能有漏洞
def call_model() -> str:
    chat_model = AgentModel("GPT")
    response = chat_model.chat(PROMPT)
    return response

class VulnAgent:
    def __init__(self, chat_id: str, user_input: str, websocket: WebSocket, user_model: ChatModel = QwenChatModel(), planner_model: ChatModel = QwenChatModel(), config_dir: str = './history'):
        self.user_model = user_model
        self.planner_model = planner_model
        self.config_dir = config_dir
        self.chat_id = chat_id
        self.user_input = user_input
        self.websocket = websocket
        
        self.is_last = False
        self.agent = None
        self.tool_status = "stop"
        self.tool = None
        self.command = None
        self.tool_result = None

        self.files = get_firmware_files(f"{self.config_dir}/{self.chat_id}")

        self._init_bot()

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        # self.selector = Selector(self.user_model)
        self.online_search_agent = OnlineSearchAgent(self.user_model)
        self.BinwalkAgent = BinwalkAgent(self.planner_model)
        self.BinaryFilterAgent = BinaryFilterAgent(self.planner_model)
        self.IDAAgent = IdaToolkit()
        self.BindiffAgent = BindiffAgent(self.chat_id)
        self.LLM_DIFF = Refiner()
        
        self.config_manager = ConfigManager(
            chat_id=self.chat_id,
            user_id=123456,
            user_name="root",
            query=self.user_input,
            upload_files=self.files,
            config_path=self.config_dir
        )
        self.plan_manager = None
        #self.chat_id = None
        self.tasks = None
        self.results = None
        self.state = ProgressEnum.NOT_STARTED
    
    async def send_message(self, content: str):
        """
        发送消息到 WebSocket
        :
        """
        system_status = {
            "status": self.state.name,
            "agent": self.agent,
            "tool": self.tool
        }

        if self.tool:
            tool_status = {
                "type": "terminal",
                "content": [
                    {
                        "user": "root@ubuntu:~$",
                        "input": self.command,
                        "output": self.tool_result
                    }
                ]
            }
        else:
            tool_status = None

        response = {
            "chat_id": self.chat_id,
            "is_last": self.is_last,
            "type": "message",
            "content": content,
            "system_status": system_status,
            "tool_status": tool_status
        }

        await self.websocket.send_json(response)
        logger.info(f"发送消息: {response}")

    async def chat(self):
        """
        聊天接口
        :param chat_id: 会话ID
        :param query: 用户查询内容
        :return: 聊天响应
        """
        # self.tasks = self.user_agent.process(query)
        # logger.info(f"Tasks: {self.tasks}")

        self.tasks = """
        ## 1.使用Binwalk提取固件文件
        ## 2.筛选出可能存在漏洞的二进制文件
        ## 3.使用IDA导出两个不同版本二进制文件的.export文件
        ## 4.使用BinDiff分析两个.export文件的差异
        ## 5.分析BinDiff的结果，找出可能存在漏洞的函数
        ## 6.使用IDA导出函数的伪C代码
        ## 7.使用Detection Agent分析函数的伪C代码
        """
        logger.info(f"Tasks: {self.tasks}")

        self.plan_manager = PlanManager(
            chat_id=self.chat_id,
            plan_path=self.config_dir,
            query=self.user_input,
            upload_files=self.files,
            plan=self.tasks
        )

        self.config_manager.update_agent_status(new_running_agent="Online Search Agent")
        self.config_manager.update_tool_status(new_running_tool="Online Search")
        self.tool = "Online Search"
        self.tool_status = "running"
        self.agent = "Online Search Agent"
        await self.send_message("正在运行 Online Search Agent...")
        search_result = self.online_search_agent.process(task_id=self.chat_id, cve_id="CVE-2019-20760")
        logger.info(f"Online search result: {search_result}")
        

        self.config_manager.update_agent_status("Online Search Agent", "Binwalk Agent")
        self.config_manager.update_tool_status("Online Search", new_running_tool="Binwalk")
        self.tool = "Binwalk"
        self.tool_status = "running"
        self.agent = "Binwalk Agent"
        self.command = "binwalk -e ..."
        await self.send_message("正在运行 Binwalk...")
        # await asyncio.sleep(10)  # 模拟处理间隔
        
        files = self.files
        
        binwalk_results = []

        for file in files:
            binwalk_result = self.BinwalkAgent.process(
                task_id=self.chat_id,
                firmware_path=str(file))
            print(binwalk_result)
            logger.info(f"Binwalk result: {binwalk_result}")
            binwalk_results.append(binwalk_result)

        
        # llm_result = call_model()
        llm_result = """- **boxlogin**: 通常负责处理用户登录，可能是绕过身份验证的主要目标。
- **uhttpd**: 作为Web服务器，它可能展现出不当的身份验证处理。
- **smbd**: 处理文件分享和访问，可能存在敏感信息的访问漏洞。
- **ntgr_sw_api**: 这个API接口可能是很多服务的交互点，需分析其实现是否存在薄弱环节。"""
        llm_result = self.BinaryFilterAgent.process(
            binary_filename="Netgear R9000",
            directory_structure=binwalk_results[0]['extracted_files_path'],
            cve_details="CVE-2019-20760"
        )
        logger.info(f"LLM result: {llm_result}")


        self.config_manager.update_agent_status("Binwalk Agent", "IDA Agent")
        self.config_manager.update_tool_status("Binwalk", "IDA Decompiler")
        self.tool = "IDA Decompiler"
        self.tool_status = "running"
        self.agent = "IDA Agent"
        # self.command = f"ida -o {output_file1} {file1}"
        # self.tool_result = result1 + "\n" + result2
        await self.send_message("正在运行 IDA Decompiler...")
        # await asyncio.sleep(10)

        # bindiff_result = self.BindiffAgent.execute(output_file1, output_file2)
        # print(bindiff_result)

        # self.config_manager.update_agent_status("IDA Agent", "Bindiff Agent")
        # self.config_manager.update_tool_status("IDA Decompiler", "Bindiff")
        # self.tool = "Bindiff"
        # self.tool_status = "running"
        # self.agent = "Bindiff Agent"
        # self.command = f"bindiff -o {bindiff_result['result'].get('output_dir')} {output_file1} {output_file2}"
        # self.tool_result = bindiff_result["result"].get("stdout", "").strip()
        # await self.send_message("正在运行 Bindiff...")
        # # await asyncio.sleep(10)

        # 使用正则表达式提取所有 `**filename**` 的内容
        matches = re.findall(r'\*\*(\w+)\*\*', llm_result)

# 拼接路径
        suspicious_files = [f"squashfs-root/usr/sbin/{name}" for name in matches]

        print(f"可疑文件: {suspicious_files}")
        idadir = os.path.join("/home/wzh/Desktop/Project/VulnAgent/history", self.chat_id, "ida")
        bindiffdir = os.path.join("/home/wzh/Desktop/Project/VulnAgent/history", self.chat_id, "bindiff")
        for file in suspicious_files:
            file1 = f"./{binwalk_results[0]['extracted_files_path']}/{file}"
            file2 = f"./{binwalk_results[1]['extracted_files_path']}/{file}"
            # 检查文件是否存在
            if not os.path.exists(file1):
                print(f"文件不存在: {file1}")
                continue
            if not os.path.exists(file2):
                print(f"文件不存在: {file2}")
                continue
            os.makedirs(idadir, exist_ok=True)
            output_path1 = os.path.join(idadir, f"{os.path.basename(file1)}")
            output_path2 = os.path.join(idadir, f"{os.path.basename(file2)}1")
            result1 = self.IDAAgent.analyze_binary(file1, output_path1, ida_version="ida32")
            result2 = self.IDAAgent.analyze_binary(file2, output_path2, ida_version="ida32")
            print(result1)
            print(result2)
            output_file1 = os.path.join("test", f"{os.path.basename(file1)}.BinExport")
            output_file2 = os.path.join("test", f"{os.path.basename(file2)}1.BinExport")
            output_dir = os.path.join(bindiffdir, f"{os.path.basename(file1)}")
            bindiff_result = self.BindiffAgent.execute(output_file1, output_file2, output_dir)
            print(bindiff_result)


        # self.config_manager.update_agent_status("Bindiff Agent", "Detection Agent")
        # self.config_manager.update_tool_status("Bindiff")
        # self.plan_manager.add_plan("## 3.使用Detection Agent分析文件")
        # self.plan_manager.add_result(bindiff_result)
        # self.agent = "Detection Agent"
        # self.tool = None
        # self.tool_status = "stop"
        # await self.send_message("正在运行 Detection Agent...")
        self.is_last = True
        self.state = ProgressEnum.COMPLETED
        response = ""

        return response

if __name__ == "__main__":
    agent = VulnAgent()
    while True:
        user_input = input("请输入漏洞分析请求（输入 exit 退出）：\n> ")
        if user_input.lower() in {"exit", "quit"}:
            print("再见！")
            break

        agent.run(user_input)
        
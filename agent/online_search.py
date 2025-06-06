from datetime import datetime
from pathlib import Path
from .base import Agent
from model import ChatModel
import os
import requests
import json
import configparser
import time

class OnlineSearchAgent(Agent):
    """
    收集指定设备固件的历史CVE信息或者搜索特定CVE详情
    支持两种搜索场景：
    1. 漏洞挖掘：根据厂商(vendor)、型号(model)、版本(version)搜索相关CVE
    2. 漏洞复现：直接通过CVE-ID搜索特定漏洞详情
    """
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.request_delay = 6  # 秒
        
    def process(self, task_id: str, vendor: str = None, model: str = None, version: str = None, cve_id: str = None) -> str:
        # 漏洞复现 直接根据cve_id搜索CVE
        if cve_id:
            return self._process_cve_search(task_id, cve_id)
        
        # 漏洞挖掘 根据设备厂商、型号、版本搜索相关的CVE
        if not task_id or not vendor:
            return json.dumps({
                'status': 'error',
                'message': '缺少必要参数: task_id 和 vendor (或者 cve_id)'
            })
        
        return self._process_device_search(task_id, vendor, model, version)
    
    # 直接搜索特定CVE-ID的详细信息
    def _process_cve_search(self, task_id: str, cve_id: str):
        work_dir = Path(f'./history/{task_id}/online_search')
        os.makedirs(work_dir, exist_ok=True)
        
        try:
            search_results = self._search_cve_by_id(cve_id)
            processed_results = self._process_search_results(search_results)
            result_file = work_dir / 'search_result.json'
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(processed_results, f, ensure_ascii=False, indent=2)
            
            # agent状态数据
            result = {
                'status': 'success',
                'search_result_path': str(result_file),
                'total_cves': processed_results.get('totalResults', 0),
                'search_mode': 'cve_id',
                'cve_id': cve_id
            }
            
            self._update_status_ini(work_dir, None, None, None, result, cve_id)
            
            return result
            
        except Exception as e:
            error_result = {
                'status': 'error',
                'message': f'执行过程中发生错误: {str(e)}'
            }
            
            # 更新状态
            self._update_status_ini(work_dir, None, None, None, error_result, cve_id)
            
            return json.dumps(error_result)
    
    # 根据厂商、型号、版本搜索相关CVE
    def _process_device_search(self, task_id: str, vendor: str, model: str = None, version: str = None):
        work_dir = Path(f'./history/{task_id}/online_search')
        os.makedirs(work_dir, exist_ok=True)
        
        try:
            search_results = self._search_cve_by_keywords(vendor, model, version)
            processed_results = self._process_search_results(search_results)
            result_file = work_dir / 'search_result.json'
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(processed_results, f, ensure_ascii=False, indent=2)
            
            # agent状态数据
            result = {
                'status': 'success',
                'search_result_path': str(result_file),
                'total_cves': processed_results.get('totalResults', 0),
                'search_mode': 'device',
                'vendor': vendor,
                'model': model,
                'version': version
            }
            
            self._update_status_ini(work_dir, vendor, model, version, result)
            
            return json.dumps(result)
            
        except Exception as e:
            error_result = {
                'status': 'error',
                'message': f'执行过程中发生错误: {str(e)}'
            }
            
            self._update_status_ini(work_dir, vendor, model, version, error_result)
            
            return json.dumps(error_result)
    
    def _search_cve_by_id(self, cve_id: str):
        params = {
            'cveId': cve_id
        }
        response = requests.get(self.api_base_url, params=params)
        if response.status_code != 200:
            raise Exception(f"NVD API请求失败，状态码: {response.status_code}, 响应: {response.text}")
        return response.json()
    
    def _search_cve_by_keywords(self, vendor: str, model: str = None, version: str = None):
        # 构建搜索关键词
        keywords = []
        if vendor:
            keywords.append(vendor)
        if model:
            keywords.append(model)
        if version:
            keywords.append(version)
        
        search_query = ' '.join(keywords)
        all_results = {
            "totalResults": 0,
            "vulnerabilities": []
        }
        
        # 分页参数
        start_index = 0
        results_per_page = 2000  # NVD API单次最大返回数量
        
        while True:
            params = {
                'keywordSearch': search_query,
                'resultsPerPage': results_per_page,
                'startIndex': start_index
            }
            
            response = requests.get(self.api_base_url, params=params)
            if response.status_code != 200:
                raise Exception(f"NVD API请求失败，状态码: {response.status_code}, 响应: {response.text}")
            result = response.json()
            all_results["totalResults"] = result.get("totalResults", 0)
            if "vulnerabilities" in result:
                all_results["vulnerabilities"].extend(result["vulnerabilities"])

            # 检查是否需要获取下一页，是则获取
            received_count = len(result.get("vulnerabilities", []))
            if received_count == 0 or start_index + received_count >= result.get("totalResults", 0):
                break
            start_index += received_count
            time.sleep(self.request_delay)
        
        return all_results
    
    def _process_search_results(self, search_results):
        processed_results = {
            "totalResults": search_results.get("totalResults", 0),
            "vulnerabilities": []
        }
        
        for vuln in search_results.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            processed_cve = {
                "cve": {
                    "id": cve_data.get("id", ""),
                    "sourceIdentifier": cve_data.get("sourceIdentifier", ""),
                    "published": cve_data.get("published", ""),
                    "lastModified": cve_data.get("lastModified", ""),
                    "descriptions": cve_data.get("descriptions", []),
                    "metrics": self._process_metrics(cve_data.get("metrics", {})),
                    "weaknesses": self._process_weaknesses(cve_data.get("weaknesses", [])),
                    "configurations": self._process_configurations(cve_data.get("configurations", [])),
                    "references": self._process_references(cve_data.get("references", []))
                }
            }
            processed_results["vulnerabilities"].append(processed_cve)
        
        return processed_results
    
    def _process_metrics(self, metrics):
        processed_metrics = {}
        
        # CVSS2
        if "cvssMetricV2" in metrics:
            cvss2_metrics = []
            for metric in metrics.get("cvssMetricV2", []):
                cvss2_metrics.append({
                    "source": metric.get("source", ""),
                    "type": metric.get("type", ""),
                    "baseScore": metric.get("cvssData", {}).get("baseScore", ""),
                    "vectorString": metric.get("cvssData", {}).get("vectorString", "")
                })
            if cvss2_metrics:
                processed_metrics["cvss2"] = cvss2_metrics
        
        # CVSS3评分
        cvss3_metrics = []
        if "cvssMetricV31" in metrics:
            for metric in metrics.get("cvssMetricV31", []):
                cvss3_metrics.append({
                    "source": metric.get("source", ""),
                    "type": metric.get("type", ""),
                    "baseScore": metric.get("cvssData", {}).get("baseScore", ""),
                    "vectorString": metric.get("cvssData", {}).get("vectorString", "")
                })
        elif "cvssMetricV30" in metrics:
            for metric in metrics.get("cvssMetricV30", []):
                cvss3_metrics.append({
                    "source": metric.get("source", ""),
                    "type": metric.get("type", ""),
                    "baseScore": metric.get("cvssData", {}).get("baseScore", ""),
                    "vectorString": metric.get("cvssData", {}).get("vectorString", "")
                })
        
        if cvss3_metrics:
            processed_metrics["cvss3"] = cvss3_metrics
        
        return processed_metrics
    
    def _process_weaknesses(self, weaknesses):
        processed_weaknesses = []
        
        for weakness in weaknesses:
            weakness_data = {
                "source": weakness.get("source", ""),
                "type": weakness.get("type", ""),
                "description": []
            }
            
            for desc in weakness.get("description", []):
                weakness_data["description"].append({
                    "lang": desc.get("lang", ""),
                    "value": desc.get("value", "")
                })
            
            processed_weaknesses.append(weakness_data)
        
        return processed_weaknesses
    
    def _process_configurations(self, configurations):
        cpe_list = []
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_data = {
                        "criteria": cpe_match.get("criteria", ""),
                        "versionStartIncluding": cpe_match.get("versionStartIncluding", ""),
                        "versionEndExcluding": cpe_match.get("versionEndExcluding", ""),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding", ""),
                        "versionEndIncluding": cpe_match.get("versionEndIncluding", ""),
                        "vulnerable": cpe_match.get("vulnerable", True)
                    }
                    
                    cpe_parts = cpe_data["criteria"].split(":")
                    if len(cpe_parts) > 4:
                        cpe_data["vendor"] = cpe_parts[3]
                        cpe_data["product"] = cpe_parts[4]
                        if len(cpe_parts) > 5:
                            cpe_data["version"] = cpe_parts[5]
                    
                    cpe_list.append(cpe_data)
        
        return cpe_list
    
    def _process_references(self, references):
        processed_references = []
        
        for ref in references:
            processed_references.append({
                "url": ref.get("url", ""),
                "tags": ref.get("tags", [])
            })
        
        return processed_references
    
    def _update_status_ini(self, work_dir, vendor=None, model=None, version=None, result=None, cve_id=None):
        status_file = work_dir / 'status.ini'
        
        config = configparser.ConfigParser()
        if os.path.exists(status_file):
            config.read(status_file)
        
        # [agent]
        if not config.has_section('agent'):
            config.add_section('agent')
        
        config.set('agent', 'status', 'stop' if result.get('status') == 'success' else 'running')
        config.set('agent', 'progress', 'search')
        config.set('agent', 'create_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S') if not config.has_option('agent', 'create_time') else config.get('agent', 'create_time'))
        config.set('agent', 'update_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # [input]
        if not config.has_section('input'):
            config.add_section('input')
        
        if cve_id:
            config.set('input', 'search_mode', 'cve_id')
            config.set('input', 'cve_id', cve_id)
        else:
            config.set('input', 'search_mode', 'device')
            if vendor:
                config.set('input', 'vendor', vendor)
            if model:
                config.set('input', 'model', model)
            if version:
                config.set('input', 'version', version)
        
        # [output]
        if not config.has_section('output'):
            config.add_section('output')
        
        if result.get('status') == 'success':
            config.set('output', 'search_result_path', result.get('search_result_path', ''))
            config.set('output', 'total_cves', str(result.get('total_cves', 0)))
        
        with open(status_file, 'w') as f:
            config.write(f)
    
    def get_result(self, task_id: str, vendor=None, model=None, version=None, cve_id=None) -> dict:
        work_dir = Path(f'./result/{task_id}/online_search')
        status_file = work_dir / 'status.ini'
        
        if not os.path.exists(status_file):
            return {
                'status': 'unknown',
                'message': f'未找到任务 {task_id} 的处理结果'
            }
        
        config = configparser.ConfigParser()
        config.read(status_file)
        
        if config.has_section('input'):
            search_mode = config.get('input', 'search_mode', fallback='device')
            
            # CVE-ID
            if search_mode == 'cve_id' and cve_id and config.get('input', 'cve_id', fallback='') == cve_id:
                specific_result = {}
                if config.has_section('output'):
                    specific_result.update({key: value for key, value in config['output'].items()})
                specific_result.update({'cve_id': cve_id})
                return specific_result
            
            # 设备-厂商-型号-版本号
            if search_mode == 'device' and vendor and model and version:
                section_name = f"{vendor}_{model}_{version}"
                if config.has_section(section_name):
                    return {key: value for key, value in config[section_name].items()}
        
        result = {}
        
        # [agent]
        if config.has_section('agent'):
            result['agent'] = {key: value for key, value in config['agent'].items()}
        
        # [input]
        if config.has_section('input'):
            result['input'] = {key: value for key, value in config['input'].items()}
        
        # [output]
        if config.has_section('output'):
            result['output'] = {key: value for key, value in config['output'].items()}
            
            if config.has_option('output', 'search_result_path'):
                search_result_path = config.get('output', 'search_result_path')
                if os.path.exists(search_result_path):
                    with open(search_result_path, 'r', encoding='utf-8') as f:
                        result['search_result'] = json.load(f)
        
        return result 
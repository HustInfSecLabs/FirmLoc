from datetime import datetime
from pathlib import Path
from .base import Agent
from model import ChatModel
from log import logger
import os
import requests
import json
import configparser
import time


# CWE 类型关键词映射，用于搜索相关CVE
CWE_SEARCH_KEYWORDS = {
    "CWE-78": ["command injection", "os command"],
    "CWE-77": ["command injection"],
    "CWE-120": ["buffer overflow", "buffer copy"],
    "CWE-121": ["stack buffer overflow", "stack-based"],
    "CWE-122": ["heap buffer overflow", "heap-based"],
    "CWE-125": ["out-of-bounds read"],
    "CWE-787": ["out-of-bounds write"],
    "CWE-22": ["path traversal", "directory traversal"],
    "CWE-23": ["path traversal", "relative path"],
    "CWE-416": ["use after free", "uaf"],
    "CWE-415": ["double free"],
    "CWE-476": ["null pointer", "null dereference"],
    "CWE-134": ["format string"],
    "CWE-190": ["integer overflow"],
    "CWE-191": ["integer underflow"],
    "CWE-798": ["hard-coded", "hardcoded credentials"],
    "CWE-259": ["hard-coded password"],
    "CWE-287": ["authentication bypass", "improper authentication"],
    "CWE-306": ["missing authentication"],
    "CWE-352": ["csrf", "cross-site request forgery"],
    "CWE-434": ["file upload", "unrestricted upload"],
    "CWE-502": ["deserialization"],
    "CWE-611": ["xxe", "xml external entity"],
    "CWE-918": ["ssrf", "server-side request forgery"],
}


class OnlineSearchAgent(Agent):
    """
    收集指定设备固件的历史CVE信息或者搜索特定CVE详情
    支持三种搜索场景：
    1. 漏洞复现：直接通过CVE-ID搜索特定漏洞详情
    2. 漏洞挖掘（设备）：根据厂商(vendor)、型号(model)、版本(version)搜索相关CVE
    3. 漏洞挖掘（CWE）：根据CWE类型和厂商搜索历史同类型CVE作为参考
    """
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.request_delay = 6  # 秒
        # 默认搜索最近5年的CVE，可配置
        self.default_years_back = 5
    
    def _get_date_range(self, years_back: int = None) -> tuple:
        """获取时间范围（ISO 8601格式）
        
        Args:
            years_back: 向前追溯的年数，默认使用self.default_years_back
        
        Returns:
            (pubStartDate, pubEndDate) 元组，格式为 'YYYY-MM-DDTHH:MM:SS.000Z'
        """
        from datetime import datetime, timedelta
        
        years = years_back if years_back is not None else self.default_years_back
        end_date = datetime.now()
        start_date = end_date - timedelta(days=years * 365)
        
        # NVD API要求的时间格式（使用Z而不是UTC-00:00）
        pub_end = end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        pub_start = start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        return pub_start, pub_end
    
    def _split_date_range_to_120_days(self, start_date_str: str, end_date_str: str) -> list:
        """将日期范围拆分为多个不超过120天的区间
        
        NVD API限制：单次请求的日期范围不能超过120天
        
        Args:
            start_date_str: 开始日期字符串
            end_date_str: 结束日期字符串
        
        Returns:
            [(start1, end1), (start2, end2), ...] 列表
        """
        from datetime import datetime, timedelta
        
        start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        ranges = []
        current_start = start_date
        max_days = 119  # 使用119天以确保不超过120天限制
        
        while current_start < end_date:
            current_end = min(current_start + timedelta(days=max_days), end_date)
            
            start_str = current_start.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_str = current_end.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            ranges.append((start_str, end_str))
            current_start = current_end + timedelta(seconds=1)  # 下一个区间从当前结束时间+1秒开始
        
        return ranges
    
    def _sort_by_published_date(self, vulnerabilities: list) -> list:
        """按发布日期排序CVE（最新的在前）
        
        Args:
            vulnerabilities: CVE列表
        
        Returns:
            排序后的CVE列表
        """
        def get_published_date(vuln):
            try:
                date_str = vuln.get("cve", {}).get("published", "")
                if date_str:
                    # 解析ISO 8601格式的日期
                    from datetime import datetime
                    return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return datetime.min
            except Exception:
                return datetime.min
        
        sorted_vulns = sorted(vulnerabilities, key=get_published_date, reverse=True)
        return sorted_vulns
        
    def process(self, task_id: str, vendor: str = None, model: str = None, 
                version: str = None, cve_id: str = None, cwe_id: str = None,
                work_mode: str = "reproduction") -> dict:
        """
        处理搜索请求
        
        Args:
            task_id: 任务ID
            vendor: 厂商名称
            model: 型号
            version: 版本
            cve_id: CVE编号（漏洞复现模式）
            cwe_id: CWE编号（漏洞挖掘模式）
            work_mode: 工作模式 - "reproduction" 或 "discovery"
        """
        # 漏洞复现模式：直接根据cve_id搜索CVE
        if work_mode == "reproduction" and cve_id:
            return self._process_cve_search(task_id, cve_id)
        
        # 漏洞挖掘模式：根据CWE类型和厂商搜索历史同类型CVE
        if work_mode == "discovery" and cwe_id:
            return self._process_cwe_discovery_search(task_id, cwe_id, vendor, model)
        
        # 兼容旧逻辑：根据设备厂商、型号、版本搜索相关的CVE
        if vendor:
            return self._process_device_search(task_id, vendor, model, version)
        
        return {
            'status': 'error',
            'message': '缺少必要参数: 需要提供 cve_id（漏洞复现）或 cwe_id（漏洞挖掘）'
        }
    
    def _process_cwe_discovery_search(self, task_id: str, cwe_id: str, 
                                       vendor: str = None, model: str = None) -> dict:
        """
        漏洞挖掘模式：根据CWE类型搜索历史同类型CVE作为参考
        
        搜索策略（优先搜索最近的CVE）：
        1. 使用CWE ID + 时间范围搜索（最近5年）
        2. 如果提供了厂商，结合厂商名称搜索
        3. 如果结果不足，逐步扩展时间范围
        4. 返回相关的CVE作为漏洞挖掘参考
        """
        work_dir = Path(f'./history/{task_id}/online_search')
        os.makedirs(work_dir, exist_ok=True)
        
        logger.info(f"漏洞挖掘搜索: CWE={cwe_id}, vendor={vendor}, model={model}")
        
        try:
            # 获取CWE相关的搜索关键词
            cwe_keywords = CWE_SEARCH_KEYWORDS.get(cwe_id.upper(), [])
            
            all_results = {
                "totalResults": 0,
                "vulnerabilities": [],
                "search_info": {
                    "mode": "discovery",
                    "cwe_id": cwe_id,
                    "vendor": vendor,
                    "model": model,
                    "keywords_used": [],
                    "time_ranges": []
                }
            }
            
            # 策略1: 使用CWE ID + 时间范围搜索（优先最近的CVE）
            # 先搜索最近5年，如果不足再扩展到10年、15年
            time_ranges = [5, 10, 15]
            target_count = 20
            
            for years_back in time_ranges:
                if len(all_results["vulnerabilities"]) >= target_count:
                    break
                
                try:
                    pub_start, pub_end = self._get_date_range(years_back)
                    logger.info(f"搜索最近 {years_back} 年的CVE: {pub_start} 到 {pub_end}")
                    
                    cwe_results = self._search_by_cwe_id(
                        cwe_id, 
                        max_results=target_count,
                        pub_start_date=pub_start,
                        pub_end_date=pub_end
                    )
                    
                    if cwe_results.get("vulnerabilities"):
                        # 按发布时间排序（最新的在前）
                        sorted_vulns = self._sort_by_published_date(cwe_results["vulnerabilities"])
                        all_results["vulnerabilities"].extend(sorted_vulns)
                        all_results["search_info"]["keywords_used"].append(f"cweId={cwe_id}")
                        all_results["search_info"]["time_ranges"].append(f"最近{years_back}年")
                        logger.info(f"CWE ID搜索（最近{years_back}年）找到 {len(sorted_vulns)} 个CVE")
                        break  # 找到足够的结果就停止
                    
                except Exception as e:
                    logger.warning(f"CWE ID搜索（最近{years_back}年）失败: {e}")
            
            # 策略2: 如果提供了厂商，结合厂商和CWE关键词搜索
            if vendor and cwe_keywords and len(all_results["vulnerabilities"]) < 15:
                for keyword in cwe_keywords[:2]:  # 限制关键词数量避免过多API调用
                    try:
                        time.sleep(self.request_delay)
                        pub_start, pub_end = self._get_date_range(5)  # 搜索最近5年
                        
                        keyword_results = self._search_cve_by_keywords(
                            vendor, 
                            keyword,  # 使用CWE关键词作为model参数
                            None,
                            max_results=10,
                            pub_start_date=pub_start,
                            pub_end_date=pub_end
                        )
                        if keyword_results.get("vulnerabilities"):
                            sorted_vulns = self._sort_by_published_date(keyword_results["vulnerabilities"])
                            all_results["vulnerabilities"].extend(sorted_vulns)
                            all_results["search_info"]["keywords_used"].append(f"{vendor} {keyword}")
                            logger.info(f"关键词'{vendor} {keyword}'搜索找到 {len(sorted_vulns)} 个CVE")
                    except Exception as e:
                        logger.warning(f"关键词搜索失败 ({vendor} {keyword}): {e}")
            
            # 策略3: 只用厂商搜索（如果没有CWE关键词或上述搜索结果太少）
            if vendor and len(all_results["vulnerabilities"]) < 5:
                try:
                    time.sleep(self.request_delay)
                    pub_start, pub_end = self._get_date_range(5)  # 搜索最近5年
                    
                    vendor_results = self._search_cve_by_keywords(
                        vendor, model, None, 
                        max_results=20,
                        pub_start_date=pub_start,
                        pub_end_date=pub_end
                    )
                    if vendor_results.get("vulnerabilities"):
                        sorted_vulns = self._sort_by_published_date(vendor_results["vulnerabilities"])
                        all_results["vulnerabilities"].extend(sorted_vulns)
                        all_results["search_info"]["keywords_used"].append(f"vendor={vendor}")
                        logger.info(f"厂商搜索找到 {len(sorted_vulns)} 个CVE")
                except Exception as e:
                    logger.warning(f"厂商搜索失败: {e}")
            
            # 去重（根据CVE ID）
            seen_cve_ids = set()
            unique_vulnerabilities = []
            for vuln in all_results["vulnerabilities"]:
                cve_id_found = vuln.get("cve", {}).get("id", "")
                if cve_id_found and cve_id_found not in seen_cve_ids:
                    seen_cve_ids.add(cve_id_found)
                    unique_vulnerabilities.append(vuln)
            
            all_results["vulnerabilities"] = unique_vulnerabilities[:30]  # 限制最多30个结果
            all_results["totalResults"] = len(all_results["vulnerabilities"])
            
            # 处理并保存结果
            processed_results = self._process_search_results(all_results)
            processed_results["search_info"] = all_results["search_info"]
            
            result_file = work_dir / 'search_result.json'
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(processed_results, f, ensure_ascii=False, indent=2)
            
            result = {
                'status': 'success',
                'search_result_path': str(result_file),
                'total_cves': processed_results.get('totalResults', 0),
                'search_mode': 'cwe_discovery',
                'cwe_id': cwe_id,
                'vendor': vendor
            }
            
            self._update_status_ini(work_dir, vendor, model, None, result, cwe_id=cwe_id)
            
            logger.info(f"漏洞挖掘搜索完成: 找到 {result['total_cves']} 个相关CVE")
            return result
            
        except Exception as e:
            logger.error(f"漏洞挖掘搜索失败: {e}")
            error_result = {
                'status': 'error',
                'message': f'漏洞挖掘搜索过程中发生错误: {str(e)}'
            }
            self._update_status_ini(work_dir, vendor, model, None, error_result, cwe_id=cwe_id)
            return error_result
    
    def _search_by_cwe_id(self, cwe_id: str, max_results: int = 20, 
                          pub_start_date: str = None, pub_end_date: str = None) -> dict:
        """根据CWE ID搜索相关CVE
        
        Args:
            cwe_id: CWE编号
            max_results: 最大结果数
            pub_start_date: 发布开始时间（ISO 8601格式，Z结尾）
            pub_end_date: 发布结束时间（ISO 8601格式，Z结尾）
        """
        all_results = {
            "totalResults": 0,
            "vulnerabilities": []
        }
        
        # 如果提供了时间范围，需要拆分为不超过120天的多个请求
        if pub_start_date and pub_end_date:
            date_ranges = self._split_date_range_to_120_days(pub_start_date, pub_end_date)
            logger.info(f"时间范围被拆分为 {len(date_ranges)} 个请求（每个不超过120天）")
            
            for i, (start, end) in enumerate(date_ranges, 1):
                if len(all_results["vulnerabilities"]) >= max_results:
                    break
                
                try:
                    logger.debug(f"请求 {i}/{len(date_ranges)}: {start} 到 {end}")
                    
                    params = {
                        'cweId': cwe_id,
                        'pubStartDate': start,
                        'pubEndDate': end,
                        'resultsPerPage': min(max_results - len(all_results["vulnerabilities"]), 100)
                    }
                    
                    response = requests.get(self.api_base_url, params=params, timeout=30)
                    if response.status_code != 200:
                        logger.warning(f"请求失败（状态码{response.status_code}），跳过此时间段")
                        continue
                    
                    result = response.json()
                    if result.get("vulnerabilities"):
                        all_results["vulnerabilities"].extend(result["vulnerabilities"])
                        all_results["totalResults"] += result.get("totalResults", 0)
                    
                    # API速率限制：请求间隔
                    if i < len(date_ranges):
                        time.sleep(self.request_delay)
                        
                except Exception as e:
                    logger.warning(f"请求时间段 {start} 到 {end} 失败: {e}")
                    continue
            
            return all_results
        
        # 没有时间范围限制，直接搜索
        params = {
            'cweId': cwe_id,
            'resultsPerPage': min(max_results, 100)
        }
        
        response = requests.get(self.api_base_url, params=params, timeout=30)
        if response.status_code != 200:
            raise Exception(f"NVD API请求失败，状态码: {response.status_code}")
        return response.json()
    
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
            
            return error_result
    
    # 根据厂商、型号、版本搜索相关CVE
    def _process_device_search(self, task_id: str, vendor: str, model: str = None, version: str = None):
        work_dir = Path(f'./history/{task_id}/online_search')
        os.makedirs(work_dir, exist_ok=True)
        
        try:
            # 默认搜索最近5年的CVE
            pub_start, pub_end = self._get_date_range(5)
            logger.info(f"设备搜索使用时间范围: {pub_start} 到 {pub_end}")
            
            search_results = self._search_cve_by_keywords(
                vendor, model, version,
                pub_start_date=pub_start,
                pub_end_date=pub_end
            )
            
            # 按发布时间排序
            if search_results.get("vulnerabilities"):
                search_results["vulnerabilities"] = self._sort_by_published_date(
                    search_results["vulnerabilities"]
                )
            
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
        response = requests.get(self.api_base_url, params=params, timeout=30)
        if response.status_code != 200:
            raise Exception(f"NVD API请求失败，状态码: {response.status_code}, 响应: {response.text}")
        return response.json()
    
    def _search_cve_by_keywords(self, vendor: str, model: str = None, version: str = None, 
                                max_results: int = None, pub_start_date: str = None, 
                                pub_end_date: str = None):
        """根据关键词搜索CVE
        
        Args:
            vendor: 厂商名称
            model: 型号（也可用于传递其他搜索关键词）
            version: 版本
            max_results: 最大结果数，如果为None则获取所有结果
            pub_start_date: 发布开始时间（ISO 8601格式，Z结尾）
            pub_end_date: 发布结束时间（ISO 8601格式，Z结尾）
        """
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
        
        # 如果提供了时间范围，需要拆分为不超过120天的多个请求
        if pub_start_date and pub_end_date:
            date_ranges = self._split_date_range_to_120_days(pub_start_date, pub_end_date)
            logger.info(f"时间范围被拆分为 {len(date_ranges)} 个请求（每个不超过120天）")
            
            for i, (start, end) in enumerate(date_ranges, 1):
                if max_results and len(all_results["vulnerabilities"]) >= max_results:
                    break
                
                try:
                    logger.debug(f"关键词搜索请求 {i}/{len(date_ranges)}: {start} 到 {end}")
                    
                    params = {
                        'keywordSearch': search_query,
                        'pubStartDate': start,
                        'pubEndDate': end,
                        'resultsPerPage': min(100, max_results - len(all_results["vulnerabilities"]) if max_results else 100)
                    }
                    
                    response = requests.get(self.api_base_url, params=params, timeout=30)
                    if response.status_code != 200:
                        logger.warning(f"关键词搜索请求失败（状态码{response.status_code}），跳过此时间段")
                        continue
                    
                    result = response.json()
                    if result.get("vulnerabilities"):
                        all_results["vulnerabilities"].extend(result["vulnerabilities"])
                        all_results["totalResults"] += result.get("totalResults", 0)
                    
                    # API速率限制：请求间隔
                    if i < len(date_ranges):
                        time.sleep(self.request_delay)
                        
                except Exception as e:
                    logger.warning(f"关键词搜索时间段 {start} 到 {end} 失败: {e}")
                    continue
            
            if max_results:
                all_results["vulnerabilities"] = all_results["vulnerabilities"][:max_results]
            
            return all_results
        
        # 没有时间范围限制，使用原有逻辑（分页）
        start_index = 0
        results_per_page = min(100, max_results) if max_results else 100
        
        while True:
            params = {
                'keywordSearch': search_query,
                'resultsPerPage': results_per_page,
                'startIndex': start_index
            }
            
            response = requests.get(self.api_base_url, params=params, timeout=30)
            if response.status_code != 200:
                raise Exception(f"NVD API请求失败，状态码: {response.status_code}, 响应: {response.text}")
            result = response.json()
            all_results["totalResults"] = result.get("totalResults", 0)
            if "vulnerabilities" in result:
                all_results["vulnerabilities"].extend(result["vulnerabilities"])

            # 检查是否达到最大结果数限制
            if max_results and len(all_results["vulnerabilities"]) >= max_results:
                all_results["vulnerabilities"] = all_results["vulnerabilities"][:max_results]
                break
            
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
    
    def _update_status_ini(self, work_dir, vendor=None, model=None, version=None, result=None, cve_id=None, cwe_id=None):
        """更新状态文件
        
        Args:
            work_dir: 工作目录
            vendor: 厂商
            model: 型号
            version: 版本
            result: 搜索结果
            cve_id: CVE编号（漏洞复现模式）
            cwe_id: CWE编号（漏洞挖掘模式）
        """
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
        elif cwe_id:
            # 漏洞挖掘模式
            config.set('input', 'search_mode', 'cwe_discovery')
            config.set('input', 'cwe_id', cwe_id)
            if vendor:
                config.set('input', 'vendor', vendor)
            if model:
                config.set('input', 'model', model)
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
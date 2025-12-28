import json
import os
from typing import Dict, List
from .base import BaseScanner

class ConfigScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.suspicious_keys = ['auto_map', 'trust_remote_code']
        self.dangerous_patterns = ['.py', 'import', 'exec', 'eval']

    def scan(self, file_path: str) -> Dict:
        """
        扫描配置文件 (.json)，检测潜在的恶意配置
        """
        self._log_scan_start(file_path)

        if not os.path.exists(file_path):
            error_msg = f"文件不存在: {file_path}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        issues = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # 检查 1: trust_remote_code
            if config.get("trust_remote_code") is True:
                issues.append("Found 'trust_remote_code': true (Allows RCE)")

            # 检查 2: auto_map (自定义代码加载)
            if "auto_map" in config:
                issues.append(f"Found 'auto_map': {config['auto_map']} (Custom Code Execution)")

        except json.JSONDecodeError as e:
            error_msg = f"JSON Error: {str(e)}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "unknown")
        except Exception as e:
            error_msg = f"扫描出错: {str(e)}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        if issues:
            result = self._create_result(False, issues, "high")
        else:
            result = self._create_result(True, [], "low")

        self._log_scan_result(result)
        return result

    def scan_file(self, file_path: str) -> bool:
        """
        兼容旧接口的方法
        """
        result = self.scan(file_path)
        return result["is_safe"]

if __name__ == "__main__":
    scanner = ConfigScanner()
    scanner.scan_file("day12/hacker_repo/config.json")

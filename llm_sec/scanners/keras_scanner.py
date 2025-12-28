import h5py
import json
import os
from typing import Dict, List
from .base import BaseScanner

class KerasScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.dangerous_layers = ['Lambda']
        self.suspicious_keywords = ['exec', 'eval', 'import', 'os.', 'subprocess', 'system']

    def scan(self, file_path: str) -> Dict:
        """
        扫描 Keras H5 文件，检测潜在的恶意层
        """
        self._log_scan_start(file_path)

        if not os.path.exists(file_path):
            error_msg = f"文件不存在: {file_path}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        issues = []
        risk_level = "low"

        try:
            with h5py.File(file_path, 'r') as f:
                if 'model_config' not in f.attrs:
                    print("⚠️ 未找到 model_config，可能不是标准的 Keras 模型。")
                    return self._create_result(True, [], "low")

                config_str = f.attrs['model_config']
                config = json.loads(config_str)

                print("📜 正在分析模型层结构...")

                def check_layers(layers_config):
                    nonlocal issues, risk_level
                    for layer in layers_config:
                        class_name = layer.get('class_name', '')

                        if class_name in self.dangerous_layers:
                            issues.append(f"发现 {class_name} 层")
                            risk_level = "high"
                            # 检查 Lambda 层的配置
                            cfg = layer.get('config', {})
                            func_code = cfg.get('function', '')
                            if func_code:
                                func_str = str(func_code)
                                # 检查是否包含可疑关键字
                                for keyword in self.suspicious_keywords:
                                    if keyword in func_str.lower():
                                        issues.append(f"函数代码包含可疑关键字: {keyword}")
                                issues.append(f"函数序列化数据: {func_str[:100]}...")

                        # 递归检查嵌套层
                        if 'layers' in layer.get('config', {}):
                            check_layers(layer['config']['layers'])

                if 'config' in config and 'layers' in config['config']:
                    check_layers(config['config']['layers'])

        except Exception as e:
            error_msg = f"扫描出错: {e}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        is_safe = len(issues) == 0
        result = self._create_result(is_safe, issues, risk_level)
        self._log_scan_result(result)
        return result

    def scan_file(self, file_path: str) -> bool:
        """
        兼容旧接口的方法
        """
        result = self.scan(file_path)
        return result["is_safe"]

if __name__ == "__main__":
    scanner = KerasScanner()
    scanner.scan_file("day10/malicious.h5")

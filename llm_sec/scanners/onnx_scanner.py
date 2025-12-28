import onnxruntime as ort
import json
import os
from typing import Dict, List
from .base import BaseScanner

class OnnxScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.suspicious_ops = [
            'ScriptOperator',  # 脚本操作符，可能执行代码
            'Loop',           # 循环操作符，可能用于DoS
            'Scan',           # 扫描操作符，可疑
        ]
        self.dangerous_metadata_keys = [
            'producer', 'domain', 'doc_string',
            'external_data', 'producer_version'
        ]

    def scan(self, file_path: str) -> Dict:
        """
        扫描ONNX模型文件，检测潜在的安全威胁
        """
        self._log_scan_start(file_path)

        if not os.path.exists(file_path):
            error_msg = f"文件不存在: {file_path}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        issues = []
        risk_level = "low"

        try:
            # 加载ONNX模型进行基本验证
            session = ort.InferenceSession(file_path)

            # 检查模型输入输出
            inputs = session.get_inputs()
            outputs = session.get_outputs()

            # 1. 检查可疑的操作符
            model_meta = session.get_modelmeta()
            custom_metadata = {}
            if hasattr(model_meta, 'custom_metadata_map'):
                custom_metadata = model_meta.custom_metadata_map

            # 检查metadata中的可疑内容
            for key, value in custom_metadata.items():
                if key in self.dangerous_metadata_keys:
                    if self._is_suspicious_metadata(key, value):
                        issues.append(f"发现可疑metadata: {key}={value}")
                        risk_level = "medium"

            # 2. 检查操作符类型
            # 注意：ONNX Runtime不直接暴露所有操作符，这里只是基础检查
            input_names = [inp.name for inp in inputs]
            output_names = [out.name for out in outputs]

            # 检查输入输出名称是否可疑
            suspicious_patterns = ['exec', 'eval', 'system', 'subprocess', 'import']
            for name in input_names + output_names:
                for pattern in suspicious_patterns:
                    if pattern.lower() in name.lower():
                        issues.append(f"发现可疑的输入/输出名称: {name}")
                        if risk_level == "low":
                            risk_level = "medium"

            # 3. 检查模型大小（过大的模型可能有隐藏payload）
            file_size = os.path.getsize(file_path)
            if file_size > 500 * 1024 * 1024:  # 500MB
                issues.append(f"模型文件过大 ({file_size/1024/1024:.1f}MB)，可能包含隐藏payload")
                risk_level = "medium"

            # 4. 尝试检查模型结构的一致性
            try:
                # 检查输入输出类型
                for inp in inputs:
                    if inp.type is None or str(inp.type) == '':
                        issues.append(f"输入 {inp.name} 类型信息缺失")
                        if risk_level == "low":
                            risk_level = "low"

                for out in outputs:
                    if out.type is None or str(out.type) == '':
                        issues.append(f"输出 {out.name} 类型信息缺失")
                        if risk_level == "low":
                            risk_level = "low"

            except Exception as e:
                issues.append(f"模型结构检查失败: {str(e)}")

        except Exception as e:
            error_msg = f"ONNX模型加载失败: {str(e)}"
            print(f"❌ {error_msg}")
            # ONNX加载失败可能是安全问题
            return self._create_result(False, [error_msg], "high")

        is_safe = len(issues) == 0
        result = self._create_result(is_safe, issues, risk_level)
        self._log_scan_result(result)
        return result

    def _is_suspicious_metadata(self, key: str, value: str) -> bool:
        """检查metadata是否可疑"""
        suspicious_patterns = [
            'exec', 'eval', 'system', 'subprocess', 'import',
            'http://', 'https://', 'ftp://', 'file://',
            'bash', 'sh', 'cmd', 'powershell'
        ]

        value_str = str(value).lower()
        return any(pattern in value_str for pattern in suspicious_patterns)

    def scan_file(self, file_path: str) -> bool:
        """
        兼容旧接口的方法
        """
        result = self.scan(file_path)
        return result["is_safe"]

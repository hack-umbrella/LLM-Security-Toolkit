import os
import json
import struct
from typing import Dict, List, Optional
from .base import BaseScanner

class ModelArchitectureScanner(BaseScanner):
    """
    通用模型架构扫描器，检测各种模型文件中的架构异常和潜在安全威胁
    """

    def __init__(self):
        super().__init__()
        self.suspicious_patterns = {
            'layer_names': [
                'malicious', 'evil', 'hack', 'exploit', 'rce', 'exec',
                'system', 'subprocess', 'eval', 'backdoor', 'trojan'
            ],
            'metadata_keys': [
                'producer', 'author', 'description', 'comment', 'note'
            ],
            'file_paths': [
                '..', '../', '\\', '\\\\', '/etc/', 'C:\\', 'cmd', 'bash'
            ]
        }

    def scan(self, file_path: str) -> Dict:
        """
        扫描模型文件，检测架构和元数据异常
        """
        self._log_scan_start(file_path)

        if not os.path.exists(file_path):
            error_msg = f"文件不存在: {file_path}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        issues = []
        risk_level = "low"

        try:
            file_ext = self._get_file_extension(file_path).lower()

            # 根据文件类型进行不同检查
            if file_ext == '.safetensors':
                issues.extend(self._scan_safetensors(file_path))
            elif file_ext in ['.bin', '.pth', '.pt']:
                issues.extend(self._scan_pytorch_file(file_path))
            elif file_ext == '.onnx':
                issues.extend(self._scan_onnx_metadata(file_path))
            elif file_ext == '.h5':
                issues.extend(self._scan_h5_metadata(file_path))
            else:
                # 通用文件检查
                issues.extend(self._scan_generic_file(file_path))

            # 检查文件大小异常
            file_size = os.path.getsize(file_path)
            size_issues = self._check_file_size_anomaly(file_size, file_ext)
            issues.extend(size_issues)

            # 确定风险等级
            risk_level = self._calculate_risk_level(issues)

        except Exception as e:
            error_msg = f"模型架构扫描失败: {str(e)}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "medium")

        is_safe = len(issues) == 0
        result = self._create_result(is_safe, issues, risk_level)
        self._log_scan_result(result)
        return result

    def _scan_safetensors(self, file_path: str) -> List[str]:
        """扫描SafeTensors文件"""
        issues = []

        try:
            # SafeTensors通常比较安全，但检查metadata
            with open(file_path, 'rb') as f:
                # 检查文件头
                header_size_bytes = f.read(8)
                if len(header_size_bytes) != 8:
                    issues.append("SafeTensors文件头不完整")
                    return issues

                header_size = struct.unpack('<Q', header_size_bytes)[0]

                if header_size > 100 * 1024 * 1024:  # 100MB
                    issues.append(f"SafeTensors头部过大: {header_size} bytes")
                    return issues

                # 读取JSON头部
                header_bytes = f.read(header_size)
                try:
                    header = json.loads(header_bytes.decode('utf-8'))

                    # 检查tensors信息
                    if '__metadata__' in header:
                        metadata = header['__metadata__']
                        issues.extend(self._check_metadata(metadata))

                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    issues.append(f"SafeTensors头部解析失败: {str(e)}")

        except Exception as e:
            issues.append(f"SafeTensors扫描失败: {str(e)}")

        return issues

    def _scan_pytorch_file(self, file_path: str) -> List[str]:
        """扫描PyTorch文件的基本架构信息"""
        issues = []

        try:
            # 检查文件是否可读
            with open(file_path, 'rb') as f:
                # 读取前几个字节检查格式
                magic_bytes = f.read(4)
                f.seek(0)

                # 检查是否是zip文件（PyTorch state_dict通常是zip格式）
                if magic_bytes == b'PK\x03\x04':
                    # 这是个zip文件，可能包含多个文件
                    issues.append("检测到压缩格式，可能包含多个组件")

        except Exception as e:
            issues.append(f"PyTorch文件基础检查失败: {str(e)}")

        return issues

    def _scan_onnx_metadata(self, file_path: str) -> List[str]:
        """扫描ONNX文件的元数据"""
        issues = []

        try:
            # 简单的文件头检查
            with open(file_path, 'rb') as f:
                header = f.read(8)
                if header[:4] != b'\x08\x01\x12\x0a':  # ONNX magic bytes
                    issues.append("ONNX文件格式不正确")

        except Exception as e:
            issues.append(f"ONNX元数据检查失败: {str(e)}")

        return issues

    def _scan_h5_metadata(self, file_path: str) -> List[str]:
        """扫描H5文件的元数据"""
        issues = []

        try:
            # 检查H5文件签名
            with open(file_path, 'rb') as f:
                signature = f.read(8)
                if signature != b'\x89HDF\r\n\x1a\n':
                    issues.append("H5文件格式不正确")

        except Exception as e:
            issues.append(f"H5元数据检查失败: {str(e)}")

        return issues

    def _scan_generic_file(self, file_path: str) -> List[str]:
        """通用文件检查"""
        issues = []

        try:
            # 检查文件名是否可疑
            filename = os.path.basename(file_path)
            for pattern in self.suspicious_patterns['layer_names']:
                if pattern in filename.lower():
                    issues.append(f"文件名包含可疑关键词: {pattern}")

            # 检查文件内容（前1KB）是否有可疑字符串
            with open(file_path, 'rb') as f:
                content = f.read(1024)
                content_str = content.decode('utf-8', errors='ignore')

                suspicious_strings = ['exec', 'eval', 'system', 'import os']
                for suspicious in suspicious_strings:
                    if suspicious in content_str:
                        issues.append(f"文件内容包含可疑字符串: {suspicious}")

        except Exception as e:
            # 静默失败，因为这是通用检查
            pass

        return issues

    def _check_metadata(self, metadata: Dict) -> List[str]:
        """检查元数据中的可疑内容"""
        issues = []

        if not isinstance(metadata, dict):
            return issues

        for key, value in metadata.items():
            if not isinstance(value, str):
                continue

            # 检查可疑的URL或路径
            for pattern in self.suspicious_patterns['file_paths']:
                if pattern in value:
                    issues.append(f"元数据 {key} 包含可疑路径: {pattern}")

            # 检查可疑的关键词
            for pattern in self.suspicious_patterns['layer_names']:
                if pattern in value.lower():
                    issues.append(f"元数据 {key} 包含可疑关键词: {pattern}")

        return issues

    def _check_file_size_anomaly(self, file_size: int, file_ext: str) -> List[str]:
        """检查文件大小是否异常"""
        issues = []

        # 根据文件类型定义合理的大小范围
        size_limits = {
            '.safetensors': 10 * 1024 * 1024 * 1024,  # 10GB
            '.bin': 5 * 1024 * 1024 * 1024,           # 5GB
            '.pth': 5 * 1024 * 1024 * 1024,           # 5GB
            '.pt': 5 * 1024 * 1024 * 1024,            # 5GB
            '.onnx': 2 * 1024 * 1024 * 1024,          # 2GB
            '.h5': 1 * 1024 * 1024 * 1024,            # 1GB
        }

        max_size = size_limits.get(file_ext, 500 * 1024 * 1024)  # 默认500MB

        if file_size > max_size:
            size_mb = file_size / 1024 / 1024
            max_mb = max_size / 1024 / 1024
            issues.append(f"文件过大 ({size_mb:.1f}MB > {max_mb:.1f}MB)，可能包含隐藏payload")

        # 检查异常小的文件（可能不是完整的模型）
        min_sizes = {
            '.safetensors': 1024,  # 1KB
            '.bin': 1024,
            '.pth': 1024,
            '.onnx': 1024,
            '.h5': 1024,
        }

        min_size = min_sizes.get(file_ext, 512)
        if file_size < min_size:
            issues.append(f"文件过小 ({file_size} bytes)，可能不是有效的模型文件")

        return issues

    def _calculate_risk_level(self, issues: List[str]) -> str:
        """根据发现的问题计算风险等级"""
        if not issues:
            return "low"

        high_risk_keywords = ['rce', 'exec', 'system', 'backdoor', 'trojan', 'malicious']
        medium_risk_keywords = ['suspicious', 'anomaly', 'large', 'metadata']

        has_high_risk = any(any(keyword in issue.lower() for keyword in high_risk_keywords) for issue in issues)
        has_medium_risk = any(any(keyword in issue.lower() for keyword in medium_risk_keywords) for issue in issues)

        if has_high_risk:
            return "high"
        elif has_medium_risk or len(issues) > 3:
            return "medium"
        else:
            return "low"

    def _get_file_extension(self, file_path: str) -> str:
        """获取文件扩展名"""
        return os.path.splitext(file_path)[1]

    def scan_file(self, file_path: str) -> bool:
        """
        兼容旧接口的方法
        """
        result = self.scan(file_path)
        return result["is_safe"]

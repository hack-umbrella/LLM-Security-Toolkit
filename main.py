#!/usr/bin/env python3
"""
LLM-Security-Toolkit: AI供应链安全审计工具
"""

import argparse
import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from llm_sec.scanners.pickle_scanner import PickleScanner
from llm_sec.scanners.config_scanner import ConfigScanner
from llm_sec.scanners.keras_scanner import KerasScanner
from llm_sec.scanners.onnx_scanner import OnnxScanner
from llm_sec.scanners.model_architecture_scanner import ModelArchitectureScanner
from llm_sec.scanners.dependency_scanner import DependencyScanner

def main():
    parser = argparse.ArgumentParser(description="LLM-Security-Toolkit: AI供应链安全审计工具")
    parser.add_argument("path", help="要扫描的文件或目录路径")
    args = parser.parse_args()

    target_path = args.path
    print(f"🔍 Starting scan on: {target_path}\n" + "="*40)

    # 简单的文件遍历逻辑
    files_to_scan = []
    if os.path.isfile(target_path):
        files_to_scan.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))

    # 实例化扫描器
    pickle_scanner = PickleScanner()
    config_scanner = ConfigScanner()
    keras_scanner = KerasScanner()
    onnx_scanner = OnnxScanner()
    arch_scanner = ModelArchitectureScanner()
    dep_scanner = DependencyScanner()

    # 开始扫描
    for file_path in files_to_scan:
        result = None
        filename = os.path.basename(file_path)

        if file_path.endswith((".bin", ".pkl", ".pt", ".pth")):
            print(f"⚡ Scanning Pickle: {filename}")
            result = pickle_scanner.scan(file_path)

        elif file_path.endswith(".json"):
            # 先检查是否是配置文件（有trust_remote_code等特征）
            try:
                with open(file_path, 'r') as f:
                    content = f.read(500)  # 读取前500字符
                    if '"trust_remote_code"' in content or '"auto_map"' in content:
                        print(f"📜 Scanning Config: {filename}")
                        result = config_scanner.scan(file_path)
                    else:
                        print(f"🏗️ Scanning Architecture: {filename}")
                        result = arch_scanner.scan(file_path)
            except:
                print(f"📜 Scanning Config: {filename}")
                result = config_scanner.scan(file_path)

        elif file_path.endswith(".h5"):
            print(f"🎯 Scanning Keras: {filename}")
            result = keras_scanner.scan(file_path)

        elif file_path.endswith(".onnx"):
            print(f"🔍 Scanning ONNX: {filename}")
            result = onnx_scanner.scan(file_path)

        elif file_path.endswith((".safetensors",)):
            print(f"🔒 Scanning SafeTensors: {filename}")
            result = arch_scanner.scan(file_path)

        elif any(filename.endswith(ext) for ext in ['requirements.txt', 'setup.py', 'Pipfile', 'pyproject.toml', 'package.json', 'yarn.lock', 'poetry.lock']):
            print(f"📦 Scanning Dependencies: {filename}")
            result = dep_scanner.scan(file_path)

        else:
            # 通用架构检查
            print(f"🔍 Scanning Generic: {filename}")
            result = arch_scanner.scan(file_path)

        # 输出结果
        if result:
            if not result['is_safe']:
                print(f"   🚨 [RISK: {result['risk_level']}] Issues found:")
                for issue in result['issues']:
                    print(f"      - {issue}")
            else:
                print("   ✅ Safe")

    print("="*40 + "\nScan Complete.")

if __name__ == "__main__":
    main()

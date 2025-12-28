#!/usr/bin/env python3
"""
LLM Security Toolkit 演示脚本
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from llm_sec.scanners.pickle_scanner import PickleScanner
from llm_sec.scanners.config_scanner import ConfigScanner
from llm_sec.scanners.keras_scanner import KerasScanner
from llm_sec.loaders.safe_loader import SafeLoader

def demo_scanners():
    """演示扫描器功能"""
    print("🚀 LLM Security Toolkit 演示")
    print("=" * 50)

    # 测试文件路径
    test_files = {
        "config": "../day12/hacker_repo/config.json",
        "pickle": "../day9/bert_model_finetuned.pth",
        "keras": "../day10/malicious.h5"
    }

    scanners = {
        "config": ConfigScanner(),
        "pickle": PickleScanner(),
        "keras": KerasScanner()
    }

    for file_type, file_path in test_files.items():
        if os.path.exists(file_path):
            print(f"\n📁 测试 {file_type.upper()} 文件: {file_path}")
            print("-" * 40)

            scanner = scanners[file_type]
            result = scanner.scan(file_path)

            status = "✅ 安全" if result["is_safe"] else f"⚠️ 发现威胁 (等级: {result['risk_level']})"
            print(f"扫描结果: {status}")

            if result["issues"]:
                print("发现问题:")
                for issue in result["issues"]:
                    print(f"  - {issue}")
        else:
            print(f"\n⚠️ 测试文件不存在: {file_path}")

    print("\n" + "=" * 50)
    print("🎉 演示完成！")

def demo_safe_loader():
    """演示安全加载器功能"""
    print("\n🛡️ SafeLoader 演示")
    print("=" * 30)

    # 测试安全的PyTorch加载
    torch_file = "../day9/bert_model_finetuned.pth"
    if os.path.exists(torch_file):
        print(f"测试安全加载 PyTorch 文件: {torch_file}")
        result = SafeLoader.load_torch_weights(torch_file)
        if result is not None:
            print("✅ 安全加载成功")
        else:
            print("❌ 加载失败或被安全机制阻止")
    else:
        print("⚠️ PyTorch测试文件不存在")

    # 测试安全的Transformers加载
    config_repo = "../day12/hacker_repo"
    if os.path.exists(config_repo):
        print(f"\n测试安全加载 Transformers 配置: {config_repo}")
        result = SafeLoader.load_transformer_config(config_repo)
        if result is not None:
            print("✅ 安全加载成功")
        else:
            print("❌ 加载失败或被安全机制阻止")
    else:
        print("\n⚠️ Transformers测试目录不存在")

if __name__ == "__main__":
    demo_scanners()
    demo_safe_loader()

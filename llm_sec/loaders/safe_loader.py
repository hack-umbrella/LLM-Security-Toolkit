import torch
import os
from transformers import AutoConfig, AutoModel
from ..utils.logger import get_logger

logger = get_logger(__name__)

class SafeLoader:
    @staticmethod
    def load_torch_weights(file_path):
        """
        安全加载 PyTorch 权重 (.bin/.pt)
        强制使用 weights_only=True
        """
        print(f"🛡️ SafeLoader: Loading {file_path} with strict security...")
        try:
            # PyTorch 2.4+ 的核心防御特性
            return torch.load(file_path, weights_only=True)
        except Exception as e:
            print(f"❌ Blocked potential RCE or loading error: {e}")
            return None

    @staticmethod
    def load_transformer_config(repo_path):
        """
        安全加载 HF Config
        强制禁用 trust_remote_code
        """
        print(f"🛡️ SafeLoader: Loading config from {repo_path}...")
        try:
            # 显式禁止远程代码
            return AutoConfig.from_pretrained(repo_path, trust_remote_code=False)
        except ValueError as e:
            if "requires you to execute the configuration file" in str(e):
                print(f"🚨 Security Alert: This model requires Remote Code Execution! Load aborted.")
            else:
                print(f"❌ Error: {e}")
            return None

    @staticmethod
    def load_transformer_model(repo_path):
        """
        安全加载 HF Model
        强制禁用 trust_remote_code
        """
        print(f"🛡️ SafeLoader: Loading model from {repo_path}...")
        try:
            return AutoModel.from_pretrained(repo_path, trust_remote_code=False)
        except ValueError as e:
            if "requires you to execute the modeling file" in str(e):
                print(f"🚨 Security Alert: This model requires Remote Code Execution! Load aborted.")
            else:
                print(f"❌ Error: {e}")
            return None

# 便捷函数
def safe_load_torch_weights(file_path):
    return SafeLoader.load_torch_weights(file_path)

def safe_load_config(repo_path):
    return SafeLoader.load_transformer_config(repo_path)

def safe_load_model(repo_path):
    return SafeLoader.load_transformer_model(repo_path)

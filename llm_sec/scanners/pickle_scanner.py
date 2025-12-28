import pickletools
import os
from typing import Dict, List
from .base import BaseScanner

class PickleScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.dangerous_modules = ['os', 'subprocess', 'sys', 'builtins', 'pickle', 'shutil']
        self.dangerous_functions = ['system', 'popen', 'exec', 'eval', 'execfile']

    def scan(self, file_path: str) -> Dict:
        """
        扫描 Pickle 文件 (.pkl, .bin 等)，检测潜在的恶意操作
        """
        self._log_scan_start(file_path)

        if not os.path.exists(file_path):
            error_msg = f"文件不存在: {file_path}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        issues = []

        try:
            with open(file_path, "rb") as f:
                # 静态分析 opcode
                ops = list(pickletools.genops(f))

            for opcode, arg, pos in ops:
                if opcode.name == "GLOBAL":
                    # 检查是否引入了敏感模块
                    arg_str = str(arg)
                    if any(x in arg_str for x in ['os', 'system', 'subprocess', 'eval', 'exec', 'posix']):
                        issues.append(f"发现风险 GLOBAL 导入: {arg_str} (偏移量 {pos})")
                elif opcode.name == "REDUCE":
                    # REDUCE 意味着函数执行，虽然不一定恶意，但值得注意
                    pass

        except Exception as e:
            error_msg = f"解析错误: {str(e)}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "unknown")

        if issues:
            result = self._create_result(False, issues, "critical")
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
    scanner = PickleScanner()
    scanner.scan_file("day9/bert_model_finetuned.pth")

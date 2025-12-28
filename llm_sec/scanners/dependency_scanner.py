import os
import re
import json
from typing import Dict, List, Set
from .base import BaseScanner

class DependencyScanner(BaseScanner):
    """
    依赖文件扫描器，检测requirements.txt、setup.py等文件中的恶意依赖
    """

    def __init__(self):
        super().__init__()
        # 已知的恶意包列表（示例）
        self.malicious_packages = {
            'malicious-package',
            'evil-lib',
            'trojan-horse',
            'backdoor-framework',
            'rce-package',
            'data-stealer',
            'keylogger-lib',
        }

        # 可疑的包名模式
        self.suspicious_patterns = [
            r'.*hack.*',
            r'.*exploit.*',
            r'.*backdoor.*',
            r'.*trojan.*',
            r'.*malware.*',
            r'.*rce.*',
            r'.*rootkit.*',
            r'.*keylogger.*',
            r'.*stealer.*',
            r'.*spy.*',
        ]

        # 支持的文件类型
        self.supported_files = {
            'requirements.txt': self._scan_requirements_txt,
            'setup.py': self._scan_setup_py,
            'Pipfile': self._scan_pipfile,
            'pyproject.toml': self._scan_pyproject_toml,
            'package.json': self._scan_package_json,
            'yarn.lock': self._scan_yarn_lock,
            'poetry.lock': self._scan_poetry_lock,
        }

    def scan(self, file_path: str) -> Dict:
        """
        扫描依赖文件
        """
        self._log_scan_start(file_path)

        if not os.path.exists(file_path):
            error_msg = f"文件不存在: {file_path}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "low")

        issues = []
        risk_level = "low"

        try:
            filename = os.path.basename(file_path)

            # 查找合适的扫描器
            scanner_func = None
            for supported_file, func in self.supported_files.items():
                if supported_file in filename:
                    scanner_func = func
                    break

            if scanner_func:
                issues = scanner_func(file_path)
            else:
                # 通用文本文件检查
                issues = self._scan_generic_text_file(file_path)

            # 分析发现的问题
            risk_level = self._calculate_risk_level(issues)

        except Exception as e:
            error_msg = f"依赖文件扫描失败: {str(e)}"
            print(f"❌ {error_msg}")
            return self._create_result(False, [error_msg], "medium")

        is_safe = len(issues) == 0
        result = self._create_result(is_safe, issues, risk_level)
        self._log_scan_result(result)
        return result

    def _scan_requirements_txt(self, file_path: str) -> List[str]:
        """扫描requirements.txt文件"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # 提取包名（处理版本说明符）
                    package_name = self._extract_package_name(line)
                    if package_name:
                        package_issues = self._check_package(package_name, line_num)
                        issues.extend(package_issues)

                    # 检查可疑的URL
                    if 'http://' in line or 'https://' in line or 'git+' in line:
                        issues.append(f"第{line_num}行: 包含外部URL引用 - {line}")

        except Exception as e:
            issues.append(f"requirements.txt解析失败: {str(e)}")

        return issues

    def _scan_setup_py(self, file_path: str) -> List[str]:
        """扫描setup.py文件"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # 查找install_requires
                install_requires_match = re.search(
                    r'install_requires\s*=\s*\[(.*?)\]',
                    content,
                    re.DOTALL
                )

                if install_requires_match:
                    requires_str = install_requires_match.group(1)
                    # 提取包名
                    packages = re.findall(r'[\'"]([^\'"]+)[\'"]', requires_str)

                    for package in packages:
                        package_issues = self._check_package(package.strip(), 0)
                        issues.extend(package_issues)

                # 检查setuptools.find_packages()调用
                if 'find_packages()' in content:
                    issues.append("使用find_packages()，可能包含意外的包")

        except Exception as e:
            issues.append(f"setup.py解析失败: {str(e)}")

        return issues

    def _scan_pipfile(self, file_path: str) -> List[str]:
        """扫描Pipfile"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # 这里可以添加Pipfile特定的解析逻辑
                # 暂时使用通用检查
                issues.extend(self._check_content_for_packages(content))

        except Exception as e:
            issues.append(f"Pipfile解析失败: {str(e)}")

        return issues

    def _scan_pyproject_toml(self, file_path: str) -> List[str]:
        """扫描pyproject.toml"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # 检查[tool.poetry.dependencies]部分
                if '[tool.poetry.dependencies]' in content:
                    # 简单的包检查
                    issues.extend(self._check_content_for_packages(content))

        except Exception as e:
            issues.append(f"pyproject.toml解析失败: {str(e)}")

        return issues

    def _scan_package_json(self, file_path: str) -> List[str]:
        """扫描package.json"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # 检查dependencies
                if 'dependencies' in data:
                    for package, version in data['dependencies'].items():
                        package_issues = self._check_package(package, 0)
                        issues.extend(package_issues)

                # 检查devDependencies
                if 'devDependencies' in data:
                    for package, version in data['devDependencies'].items():
                        package_issues = self._check_package(package, 0)
                        issues.extend(package_issues)

        except Exception as e:
            issues.append(f"package.json解析失败: {str(e)}")

        return issues

    def _scan_yarn_lock(self, file_path: str) -> List[str]:
        """扫描yarn.lock"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # 检查可疑的包引用
                issues.extend(self._check_content_for_packages(content))

        except Exception as e:
            issues.append(f"yarn.lock解析失败: {str(e)}")

        return issues

    def _scan_poetry_lock(self, file_path: str) -> List[str]:
        """扫描poetry.lock"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # 检查包版本和依赖
                issues.extend(self._check_content_for_packages(content))

        except Exception as e:
            issues.append(f"poetry.lock解析失败: {str(e)}")

        return issues

    def _scan_generic_text_file(self, file_path: str) -> List[str]:
        """通用文本文件检查"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                issues.extend(self._check_content_for_packages(content))

        except Exception as e:
            issues.append(f"文件读取失败: {str(e)}")

        return issues

    def _extract_package_name(self, line: str) -> str:
        """从依赖行中提取包名"""
        # 处理各种版本说明符
        line = line.split('#')[0].strip()  # 移除注释
        line = re.split(r'[><=~!,\s]', line)[0]  # 分割并取第一个部分
        return line.strip()

    def _check_package(self, package_name: str, line_num: int = 0) -> List[str]:
        """检查单个包是否有问题"""
        issues = []

        # 检查已知恶意包
        if package_name.lower() in self.malicious_packages:
            issue = f"发现已知恶意包: {package_name}"
            if line_num > 0:
                issue += f" (第{line_num}行)"
            issues.append(issue)

        # 检查可疑的包名模式
        for pattern in self.suspicious_patterns:
            if re.match(pattern, package_name.lower()):
                issue = f"包名匹配可疑模式: {package_name} (模式: {pattern})"
                if line_num > 0:
                    issue += f" (第{line_num}行)"
                issues.append(issue)
                break

        # 检查包名是否太短或太长
        if len(package_name) < 2:
            issue = f"包名过短: {package_name}"
            if line_num > 0:
                issue += f" (第{line_num}行)"
            issues.append(issue)

        if len(package_name) > 100:
            issue = f"包名过长: {package_name[:50]}..."
            if line_num > 0:
                issue += f" (第{line_num}行)"
            issues.append(issue)

        return issues

    def _check_content_for_packages(self, content: str) -> List[str]:
        """在内容中查找可能的包引用"""
        issues = []

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 查找可能的包名模式
            # 这是一个简单的启发式方法
            words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9\-_\.]*\b', line)

            for word in words:
                if 3 <= len(word) <= 50:  # 合理的包名长度
                    package_issues = self._check_package(word, line_num)
                    issues.extend(package_issues)

        return issues

    def _calculate_risk_level(self, issues: List[str]) -> str:
        """计算风险等级"""
        if not issues:
            return "low"

        # 统计不同类型的风险
        malicious_count = sum(1 for issue in issues if '恶意包' in issue or '已知恶意' in issue)
        suspicious_count = sum(1 for issue in issues if '可疑' in issue)

        if malicious_count > 0:
            return "critical"
        elif suspicious_count > 2 or len(issues) > 5:
            return "high"
        elif len(issues) > 0:
            return "medium"
        else:
            return "low"

    def scan_file(self, file_path: str) -> bool:
        """
        兼容旧接口的方法
        """
        result = self.scan(file_path)
        return result["is_safe"]

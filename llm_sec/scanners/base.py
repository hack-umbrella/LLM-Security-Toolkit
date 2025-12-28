from abc import ABC, abstractmethod
from typing import Dict, List
from ..utils.logger import get_logger

logger = get_logger(__name__)

class BaseScanner(ABC):
    """
    扫描器基类，定义统一的扫描接口
    """

    def __init__(self):
        self.name = self.__class__.__name__

    @abstractmethod
    def scan(self, file_path: str) -> Dict:
        """
        扫描文件，返回标准化的结果字典

        Args:
            file_path: 要扫描的文件路径

        Returns:
            dict: 扫描结果，格式如下：
            {
                "is_safe": bool,        # 是否安全
                "issues": List[str],    # 发现的问题列表
                "risk_level": str,      # 风险等级: "low", "medium", "high", "critical"
                "details": Dict         # 额外详细信息
            }
        """
        pass

    def _create_result(self, is_safe: bool, issues: List[str] = None,
                      risk_level: str = "low", details: Dict = None) -> Dict:
        """
        创建标准化的扫描结果
        """
        if issues is None:
            issues = []

        if details is None:
            details = {}

        # 根据问题数量和内容自动调整风险等级
        if not is_safe and risk_level == "low":
            if len(issues) > 2:
                risk_level = "medium"
            if any("高危" in issue or "critical" in issue.lower() for issue in issues):
                risk_level = "high"

        return {
            "is_safe": is_safe,
            "issues": issues,
            "risk_level": risk_level,
            "details": details
        }

    def _log_scan_start(self, file_path: str):
        """记录扫描开始"""
        logger.info(f"🔍 [{self.name}] 开始扫描: {file_path}")

    def _log_scan_result(self, result: Dict):
        """记录扫描结果"""
        status = "✅ 安全" if result["is_safe"] else f"⚠️ 发现威胁 (风险等级: {result['risk_level']})"
        logger.info(f"[{self.name}] 扫描完成: {status}")
        if result["issues"]:
            for issue in result["issues"]:
                logger.warning(f"  - {issue}")

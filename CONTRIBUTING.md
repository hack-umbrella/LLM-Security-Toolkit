# 🤝 贡献指南

欢迎为 LLM Security Toolkit 贡献代码！这个项目的核心价值是**把AI安全从"艺术"变成"科学"**，我们致力于创建一个规范化、系统化的AI安全工具平台。

## 🎯 贡献价值

通过为这个项目贡献，你将：
- 🔄 **自动化安全研究**：将个人技巧变成可复用工具
- 📏 **规范化安全实践**：建立标准化的安全检测流程
- 🌍 **影响AI安全社区**：让更多人能使用系统化的安全工具

## 🚀 快速开始

### 环境设置

```bash
# 克隆项目
git clone https://github.com/your-org/llm-sec-toolkit.git
cd llm-sec-toolkit

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 运行测试
python demo.py
```

### 代码结构理解

```
llm_sec/
├── scanners/     # 静态扫描器 - 第一道防线
│   ├── base.py           # 🔧 扫描器基类 (所有扫描器都继承这个)
│   ├── pickle_scanner.py # 📦 Pickle文件扫描
│   ├── config_scanner.py # ⚙️ 配置文件扫描
│   └── keras_scanner.py  # 🎯 Keras模型扫描
├── loaders/      # 安全加载器 - 运行时防御
│   └── safe_loader.py    # 🛡️ 强制安全加载
├── redteam/      # 红队测试 - 动态攻击 (待开发)
└── utils/        # 工具类
    └── logger.py         # 📝 统一日志
```

## 💡 贡献类型

### 1. 🔍 新增扫描器 (最高优先级)

为新的AI框架或文件类型添加扫描器：

```python
# llm_sec/scanners/your_scanner.py
from .base import BaseScanner

class YourScanner(BaseScanner):
    def scan(self, file_path: str) -> Dict:
        # 实现你的扫描逻辑
        pass
```

**扫描器模板**：
```python
class NewScanner(BaseScanner):
    def scan(self, file_path: str) -> Dict:
        # 1. 文件存在性检查
        if not os.path.exists(file_path):
            return self._create_result(False, ["文件不存在"], "low")

        # 2. 你的检测逻辑
        issues = []
        # ... 检测代码 ...

        # 3. 返回标准化结果
        if issues:
            return self._create_result(False, issues, "high")
        return self._create_result(True, [], "low")
```

### 2. 🔴 红队攻击模块

将你发现的攻击技巧自动化：

```python
# llm_sec/redteam/jailbreak_attacks.py
class JailbreakAttacks:
    @staticmethod
    def dan_attack(model, prompt):
        """DAN (Do Anything Now) 攻击"""
        # 实现攻击逻辑
        pass

    @staticmethod
    def prefix_injection(model, prompt):
        """前缀注入攻击"""
        # 实现攻击逻辑
        pass
```

### 3. 🛡️ 安全加载器扩展

为新的框架添加安全加载支持：

```python
# llm_sec/loaders/safe_loader.py
class SafeLoader:
    @staticmethod
    def load_safe_ml_model(file_path):
        """安全加载ML模型"""
        # 实现安全加载逻辑
        pass
```

### 4. 📊 新增检测规则

为现有扫描器添加新的威胁检测：

```python
# 在现有扫描器中添加
def _check_new_threat(self, content) -> List[str]:
    """检测新的威胁类型"""
    issues = []
    # 你的检测逻辑
    return issues
```

## 📋 开发工作流

### 1. 选择任务
查看 [Issues](../../issues) 或 [Projects](../../projects)，选择你感兴趣的任务。

### 2. 创建分支
```bash
git checkout -b feature/your-feature-name
```

### 3. 编写代码
- 遵循现有的代码风格
- 添加必要的测试
- 更新文档

### 4. 测试你的更改
```bash
# 运行演示脚本
python demo.py

# 测试你的新功能
python -c "from llm_sec.scanners.your_scanner import YourScanner; print('测试成功')"
```

### 5. 提交更改
```bash
git add .
git commit -m "feat: 添加新功能

- 实现了XXX检测
- 修复了XXX问题
- 优化了XXX性能

Closes #123"
```

### 6. 创建 Pull Request
- 详细描述你的更改
- 引用相关的 Issue
- 请求审查

## 🎨 代码规范

### Python 代码风格
- 使用 `black` 格式化代码
- 使用 `flake8` 检查代码质量
- 添加类型提示 (typing)
- 编写清晰的文档字符串

### 提交信息格式
```
type(scope): description

[optional body]

[optional footer]
```

类型包括：
- `feat`: 新功能
- `fix`: 修复bug
- `docs`: 文档更新
- `style`: 代码风格调整
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具相关

### 测试要求
- 为新功能添加单元测试
- 确保现有测试通过
- 测试恶意和正常样本

## 🔧 架构原则

### 1. 🔌 插件化设计
所有扫描器都继承 `BaseScanner`，保证接口一致性。

### 2. 📊 标准化输出
所有扫描结果都遵循统一格式：
```python
{
    "is_safe": bool,
    "issues": List[str],
    "risk_level": str,
    "details": Dict
}
```

### 3. 🛡️ 安全优先
- 默认启用最严格的安全设置
- 明确标识潜在风险
- 提供安全替代方案

### 4. 📈 可扩展性
- 模块化设计便于添加新功能
- 清晰的抽象层
- 统一的配置管理

## 🎯 优先级任务

### 🔥 高优先级 (立即需要)
1. **新框架支持**: TensorFlow, JAX, ONNX 扫描器
2. **云服务集成**: AWS S3, HuggingFace Hub 安全扫描
3. **性能优化**: 大文件扫描优化
4. **CI/CD**: 自动化测试和发布

### 📈 中优先级 (近期需要)
1. **红队工具**: 自动化jailbreak攻击
2. **隐私检测**: 成员推理攻击检测
3. **水印检测**: 模型水印完整性验证
4. **报告生成**: 详细的安全审计报告

### 🔮 长期规划 (未来扩展)
1. **分布式扫描**: 支持大规模模型仓库扫描
2. **实时监控**: 生产环境运行时监控
3. **AI辅助**: 使用AI辅助发现新威胁
4. **标准制定**: 推动AI安全标准制定

## 💬 交流与支持

- 📧 **邮件**: 加入开发邮件组
- 💬 **Discord**: 实时讨论技术问题
- 📋 **Issues**: 报告bug或建议新功能
- 🏷️ **Discussions**: 分享想法和最佳实践

## 🙏 贡献者认可

所有贡献者都会：
- 被列在项目贡献者列表中
- 在发布说明中被提及
- 获得社区认可

**让我们一起把AI安全变得更加系统化和可访问！** 🚀🛡️

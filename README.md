# LLM Security Toolkit (LLM安全工具包)   枇杷熟了团队
**知识星球优惠卷享受企业内测版** 

<img width="360" height="346" alt="image" src="https://github.com/user-attachments/assets/228ea817-cbf1-4f6f-80ff-217039bfd5c4" />


🚀 **把AI安全从"艺术"变成"科学"** 🚀

一个专为大语言模型安全设计的开源工具包，将之前的手动安全技巧自动化规范化。不仅提供静态查毒能力，还预留了动态测毒和红队渗透的完整框架，让AI安全研究变得系统化和可复用。

**核心价值**：
- 🔄 **自动化**：将手动安全技巧变成可复用的工具
- 📏 **规范化**：清晰代码结构，方便社区贡献，开源友好
- 🎯 **完整性**：从静态扫描到动态测试的全链条安全能力

## 🏗️ 项目架构

```
llm-sec-toolkit/
├── assets/                  # 测试用的样本 (毒模型、毒配置)
├── llm_sec/                 # 核心代码包
│   ├── __init__.py
│   ├── scanners/            # [静态防御] 扫描器模块
│   │   ├── __init__.py
│   │   ├── base.py         # 扫描器基类
│   │   ├── pickle_scanner.py    # 负责扫 .bin/.pkl (Pickle文件)
│   │   ├── config_scanner.py    # 负责扫 .json (配置文件)
│   │   └── keras_scanner.py     # 负责扫 .h5 (Keras模型)
│   ├── loaders/             # [运行时防御] 安全加载器
│   │   ├── __init__.py
│   │   └── safe_loader.py       # 封装 torch.load 等函数
│   ├── redteam/             # [动态攻击] 红队测试模块 (预留)
│   │   └── __init__.py
│   └── utils/               # 工具类
│       ├── __init__.py
│       └── logger.py        # 日志工具
├── main.py                  # CLI 入口
├── demo.py                  # 演示脚本
└── requirements.txt         # 依赖项
```

## 🚀 快速开始

### 安装依赖

```bash
cd llm-sec-toolkit
pip install -r requirements.txt
```

### 使用方式

#### CLI工具

```bash
# 扫描PyTorch模型文件
python main.py scan path/to/model.pth

# 扫描配置文件
python main.py scan path/to/config.json

# 扫描Keras模型
python main.py scan path/to/model.h5

# 安全加载模型
python main.py load torch path/to/model.pth --weights-only
```

#### Web界面 (可选)

```bash
# 安装额外依赖
pip install flask

# 启动Web界面
python web_ui.py

# 访问 http://localhost:5500
```

**Web界面特性**：
- 📁 **拖拽上传**：支持拖拽文件或点击选择
- 🔍 **自动扫描**：上传后自动检测文件类型并扫描
- 📊 **实时结果**：直观的扫描结果展示和统计
- 🎨 **现代化UI**：响应式设计，支持移动端

#### 运行演示
<img width="2650" height="1916" alt="image" src="https://github.com/user-attachments/assets/613a2549-e36f-4713-a261-82fb4ec23db0" />

```bash
python demo.py
```

## 🔍 支持的扫描类型

### 1. Pickle文件扫描器 (PickleScanner)
- **文件类型**: `.pkl`, `.bin`, `.pth`, `.pt`
- **检测内容**:
  - 危险模块引入 (`os`, `subprocess`, `sys`, `eval`, `exec`)
  - 可疑的GLOBAL指令
  - 函数执行动作 (REDUCE)

### 2. 配置文件扫描器 (ConfigScanner)
- **文件类型**: `.json`
- **检测内容**:
  - `trust_remote_code` 设置
  - 可疑的 `auto_map` 引用
  - 其他敏感配置项

### 3. Keras模型扫描器 (KerasScanner)
- **文件类型**: `.h5`
- **检测内容**:
  - Lambda层 (可能包含恶意代码)
  - 可疑的函数序列化数据
  - 危险的关键字 (`exec`, `eval`, `import`, `os.system`)

### 4. ONNX模型扫描器 (OnnxScanner)
- **文件类型**: `.onnx`
- **检测内容**:
  - 可疑的操作符和脚本执行
  - 异常的元数据和配置
  - 文件结构完整性检查

### 5. 模型架构扫描器 (ModelArchitectureScanner)
- **文件类型**: `.safetensors`, 通用模型文件
- **检测内容**:
  - SafeTensors文件结构异常
  - 元数据中的可疑内容
  - 文件大小和格式异常
  - 通用安全检查

### 6. 依赖文件扫描器 (DependencyScanner)
- **文件类型**: `requirements.txt`, `setup.py`, `package.json`等
- **检测内容**:
  - 已知恶意包
  - 可疑的包命名模式
  - 外部URL引用
  - 依赖安全风险

## 🛡️ 安全加载器

`SafeLoader` 提供了在加载前自动进行安全扫描的功能：

```python
from llm_sec.loaders.safe_loader import safe_torch_load

# 安全加载PyTorch模型
model = safe_torch_load('model.pth', weights_only=True)
```

## 📊 扫描结果格式

所有扫描器返回统一的标准化结果：

```python
{
    "is_safe": bool,        # 是否安全
    "issues": List[str],    # 发现的问题列表
    "risk_level": str,      # 风险等级: "low", "medium", "high", "critical"
    "details": Dict         # 额外详细信息
}
```

## 🧪 测试样本

`assets/` 目录包含测试用的恶意样本文件：

- `bert_model_finetuned.pth` - 正常PyTorch模型
- `malicious.h5` - 包含Lambda层的恶意Keras模型
- `config.json` - 包含 `trust_remote_code: true` 的恶意配置
- `adapter_model.bin` - LoRA适配器文件

## 📝 开发计划

### 第一道防线 (已完成)
- ✅ 静态扫描与安全加载
- ✅ Pickle文件扫描
- ✅ 配置文件扫描
- ✅ Keras模型扫描

### 第二道防线 (预留)
- 🔄 运行时动态检测
- 🔄 模型行为监控

### 第三道防线 (预留)
- 🔄 红队测试模块
- 🔄 Jailbreak攻击检测
- 🔄 隐私泄露检测

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个工具包！

## ⚠️ 免责声明

本工具包仅用于安全研究和教育目的。请勿用于非法活动。使用者需自行承担使用风险。

## 📄 许可证

MIT License

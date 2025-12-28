#!/usr/bin/env python3
"""
LLM Security Toolkit - Web界面 (可选功能)
基于Flask的轻量级Web界面，支持文件上传和自动扫描
"""

from flask import Flask, render_template, request, jsonify
import os
import sys
import tempfile
import shutil
from pathlib import Path
from werkzeug.utils import secure_filename

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from llm_sec.scanners.pickle_scanner import PickleScanner
from llm_sec.scanners.config_scanner import ConfigScanner
from llm_sec.scanners.keras_scanner import KerasScanner
from llm_sec.scanners.onnx_scanner import OnnxScanner
from llm_sec.scanners.model_architecture_scanner import ModelArchitectureScanner
from llm_sec.scanners.dependency_scanner import DependencyScanner

app = Flask(__name__)

# 配置上传
UPLOAD_FOLDER = tempfile.mkdtemp()
ALLOWED_EXTENSIONS = {'pth', 'pkl', 'bin', 'json', 'h5'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

# 初始化扫描器
scanners = {
    'pickle': PickleScanner(),
    'config': ConfigScanner(),
    'keras': KerasScanner(),
    'onnx': OnnxScanner(),
    'architecture': ModelArchitectureScanner(),
    'dependency': DependencyScanner()
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_scanner_for_file(filename):
    """根据文件扩展名选择扫描器"""
    ext = filename.rsplit('.', 1)[1].lower()
    base_name = filename.lower()

    # 依赖文件
    if any(base_name.endswith(dep_file) for dep_file in [
        'requirements.txt', 'setup.py', 'pipfile', 'pyproject.toml',
        'package.json', 'yarn.lock', 'poetry.lock'
    ]):
        return scanners['dependency']

    # 模型文件
    if ext in ['pth', 'pkl', 'bin']:
        return scanners['pickle']
    elif ext == 'onnx':
        return scanners['onnx']
    elif ext == 'safetensors':
        return scanners['architecture']
    elif ext == 'h5':
        return scanners['keras']
    elif ext == 'json':
        # 检查是否是配置文件
        try:
            # 这里简化检查，实际应该读取文件内容
            return scanners['config']
        except:
            return scanners['architecture']

    return scanners['architecture']  # 默认使用架构扫描器

@app.route('/')
def index():
    """主页"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    """扫描文件API"""
    try:
        file_path = request.json.get('file_path', '')
        scan_type = request.json.get('scan_type', 'auto')

        if not os.path.exists(file_path):
            return jsonify({
                'success': False,
                'error': f'文件不存在: {file_path}'
            })

        # 自动检测扫描类型
        if scan_type == 'auto':
            ext = Path(file_path).suffix.lower()
            if ext in ['.pkl', '.bin', '.pth', '.pt']:
                scanner = scanners['pickle']
            elif ext == '.json':
                scanner = scanners['config']
            elif ext == '.h5':
                scanner = scanners['keras']
            else:
                return jsonify({
                    'success': False,
                    'error': f'不支持的文件类型: {ext}'
                })
        else:
            scanner = scanners.get(scan_type)
            if not scanner:
                return jsonify({
                    'success': False,
                    'error': f'未知扫描类型: {scan_type}'
                })

        # 执行扫描
        result = scanner.scan(file_path)

        return jsonify({
            'success': True,
            'result': {
                'is_safe': result['is_safe'],
                'issues': result['issues'],
                'risk_level': result['risk_level']
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/upload_scan', methods=['POST'])
def upload_scan():
    """上传文件并自动扫描"""
    try:
        if 'files' not in request.files:
            return jsonify({
                'success': False,
                'error': '没有上传文件'
            })

        files = request.files.getlist('files')
        if not files or files[0].filename == '':
            return jsonify({
                'success': False,
                'error': '没有选择文件'
            })

        results = []

        for file in files:
            if file and allowed_file(file.filename):
                # 保存文件到临时目录
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                try:
                    # 获取对应的扫描器
                    scanner = get_scanner_for_file(filename)
                    if scanner:
                        # 执行扫描
                        result = scanner.scan(file_path)
                        results.append({
                            'file_name': filename,
                            'is_safe': result['is_safe'],
                            'issues': result['issues'],
                            'risk_level': result['risk_level']
                        })
                    else:
                        results.append({
                            'file_name': filename,
                            'is_safe': False,
                            'issues': ['不支持的文件类型'],
                            'risk_level': 'unknown'
                        })

                finally:
                    # 清理临时文件
                    try:
                        os.remove(file_path)
                    except:
                        pass  # 忽略删除错误

            else:
                results.append({
                    'file_name': file.filename,
                    'is_safe': False,
                    'issues': ['不支持的文件类型'],
                    'risk_level': 'unknown'
                })

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/batch_scan', methods=['POST'])
def batch_scan():
    """批量扫描目录"""
    try:
        dir_path = request.json.get('dir_path', '')

        if not os.path.exists(dir_path):
            return jsonify({
                'success': False,
                'error': f'目录不存在: {dir_path}'
            })

        results = []
        total_files = 0
        safe_files = 0

        # 遍历目录
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                total_files += 1

                # 选择扫描器
                ext = Path(file_path).suffix.lower()
                scanner = None

                if ext in ['.pkl', '.bin', '.pth', '.pt']:
                    scanner = scanners['pickle']
                elif ext == '.json':
                    scanner = scanners['config']
                elif ext == '.h5':
                    scanner = scanners['keras']

                if scanner:
                    result = scanner.scan(file_path)
                    if result['is_safe']:
                        safe_files += 1

                    results.append({
                        'file': os.path.relpath(file_path, dir_path),
                        'is_safe': result['is_safe'],
                        'issues': result['issues'],
                        'risk_level': result['risk_level']
                    })

        return jsonify({
            'success': True,
            'summary': {
                'total_files': total_files,
                'scanned_files': len(results),
                'safe_files': safe_files,
                'risky_files': len(results) - safe_files
            },
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    print("🚀 LLM Security Toolkit Web界面")
    print("📱 访问 http://localhost:5000 开始使用")
    print("⚠️  这是一个基础版本，可根据需要扩展")

    app.run(debug=True, host='0.0.0.0', port=5500)

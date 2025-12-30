#!/usr/bin/env python3
"""
analyzer.py - MongoDB Memory Leak Data Analyzer and Visualizer

基于JDumpSpider的设计理念，为mongobleed泄露的内存数据提供结构化分析和可视化
"""

import re
import json
import argparse
from collections import defaultdict, Counter
from typing import List, Dict, Any, Set
from html import escape as html_escape


class BaseAnalyzer:
    """分析器基类 - 类似于JDumpSpider的ISpider接口"""
    
    def get_name(self) -> str:
        """返回分析器名称"""
        raise NotImplementedError
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        """分析数据并返回结果"""
        raise NotImplementedError
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化输出结果"""
        if not result or not result.get('findings'):
            return "未发现相关数据\n"
        return json.dumps(result, indent=2, ensure_ascii=False)


class StringExtractor(BaseAnalyzer):
    """字符串提取器 - 类似于ExportAllString"""
    
    def get_name(self) -> str:
        return "字符串提取"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        # 提取可打印字符串（最小长度4）
        strings = []
        pattern = rb'[\x20-\x7E]{4,}'
        
        for match in re.finditer(pattern, data):
            s = match.group().decode('ascii', errors='ignore')
            strings.append({
                'offset': match.start(),
                'length': len(s),
                'content': s
            })
        
        return {
            'total_strings': len(strings),
            'findings': strings[:500]  # 限制数量避免过多
        }
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result.get('findings'):
            return "未发现字符串\n"
        
        output = f"找到 {result['total_strings']} 个字符串（显示前500个）:\n\n"
        for item in result['findings'][:100]:
            output += f"[偏移: {item['offset']:6d}] {item['content']}\n"
        return output


class CredentialHunter(BaseAnalyzer):
    """凭证搜索器 - 类似于UserPassSearcher01"""
    
    def get_name(self) -> str:
        return "凭证搜索"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        findings = defaultdict(list)
        
        patterns = {
            'passwords': [
                rb'password["\s:=]+([^\s\x00]{4,})',
                rb'passwd["\s:=]+([^\s\x00]{4,})',
                rb'pwd["\s:=]+([^\s\x00]{4,})',
            ],
            'usernames': [
                rb'username["\s:=]+([^\s\x00]{3,})',
                rb'user["\s:=]+([^\s\x00]{3,})',
                rb'login["\s:=]+([^\s\x00]{3,})',
            ],
            'api_keys': [
                rb'api[_-]?key["\s:=]+([A-Za-z0-9_-]{16,})',
                rb'apikey["\s:=]+([A-Za-z0-9_-]{16,})',
            ],
            'tokens': [
                rb'token["\s:=]+([A-Za-z0-9_.-]{16,})',
                rb'auth["\s:=]+([A-Za-z0-9_.-]{16,})',
            ],
            'secrets': [
                rb'secret["\s:=]+([A-Za-z0-9_-]{8,})',
            ],
            'aws_keys': [
                rb'(AKIA[0-9A-Z]{16})',
            ],
            'mongodb_uris': [
                rb'mongodb://[^\s\x00]+',
                rb'mongodb\+srv://[^\s\x00]+',
            ],
        }
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                for match in re.finditer(pattern, data, re.IGNORECASE):
                    findings[category].append({
                        'offset': match.start(),
                        'value': match.group(1 if match.lastindex else 0).decode('utf-8', errors='replace')[:200]
                    })
        
        # 去重
        for category in findings:
            seen = set()
            unique = []
            for item in findings[category]:
                if item['value'] not in seen:
                    seen.add(item['value'])
                    unique.append(item)
            findings[category] = unique
        
        return dict(findings)
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result:
            return "未发现凭证信息\n"
        
        output = ""
        for category, items in result.items():
            if items:
                output += f"\n{category.upper()}:\n"
                output += "-" * 60 + "\n"
                for item in items[:20]:  # 限制每类显示数量
                    output += f"  偏移 {item['offset']:6d}: {item['value']}\n"
        return output


class JSONExtractor(BaseAnalyzer):
    """JSON数据提取器"""
    
    def get_name(self) -> str:
        return "JSON数据提取"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        findings = []
        
        # 查找可能的JSON对象
        pattern = rb'\{[^\x00]{10,500}\}'
        
        for match in re.finditer(pattern, data):
            try:
                json_str = match.group().decode('utf-8', errors='ignore')
                # 尝试解析JSON
                parsed = json.loads(json_str)
                findings.append({
                    'offset': match.start(),
                    'data': parsed
                })
            except:
                pass
        
        return {'findings': findings}
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result.get('findings'):
            return "未发现有效JSON数据\n"
        
        output = f"找到 {len(result['findings'])} 个JSON对象:\n\n"
        for item in result['findings'][:50]:
            output += f"偏移 {item['offset']:6d}:\n"
            output += json.dumps(item['data'], indent=2, ensure_ascii=False) + "\n\n"
        return output


class BSONFieldAnalyzer(BaseAnalyzer):
    """BSON字段名分析器 - MongoDB特定"""
    
    def get_name(self) -> str:
        return "BSON字段分析"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        # 查找可能的BSON字段名（以null结尾的字符串）
        field_names = []
        pattern = rb'([a-zA-Z_][a-zA-Z0-9_\.]{1,50})\x00'
        
        for match in re.finditer(pattern, data):
            field_name = match.group(1).decode('utf-8', errors='ignore')
            field_names.append({
                'offset': match.start(),
                'name': field_name
            })
        
        # 统计频率
        name_counts = Counter([f['name'] for f in field_names])
        
        return {
            'total_fields': len(field_names),
            'unique_fields': len(name_counts),
            'top_fields': name_counts.most_common(50),
            'all_fields': field_names[:1000]
        }
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result.get('total_fields'):
            return "未发现BSON字段\n"
        
        output = f"找到 {result['total_fields']} 个字段名（{result['unique_fields']} 个唯一）:\n\n"
        output += "出现频率最高的字段:\n"
        for name, count in result['top_fields']:
            output += f"  {count:4d}x  {name}\n"
        return output


class EmailExtractor(BaseAnalyzer):
    """邮箱地址提取器"""
    
    def get_name(self) -> str:
        return "邮箱地址提取"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        pattern = rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = set()
        
        for match in re.finditer(pattern, data):
            email = match.group().decode('utf-8', errors='ignore')
            emails.add(email)
        
        return {'findings': sorted(list(emails))}
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result.get('findings'):
            return "未发现邮箱地址\n"
        
        output = f"找到 {len(result['findings'])} 个邮箱地址:\n"
        for email in result['findings']:
            output += f"  {email}\n"
        return output


class IPAddressExtractor(BaseAnalyzer):
    """IP地址提取器"""
    
    def get_name(self) -> str:
        return "IP地址提取"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = set()
        
        for match in re.finditer(pattern, data):
            ip = match.group().decode('utf-8')
            # 验证IP地址
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                ips.add(ip)
        
        return {'findings': sorted(list(ips))}
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result.get('findings'):
            return "未发现IP地址\n"
        
        output = f"找到 {len(result['findings'])} 个IP地址:\n"
        for ip in result['findings']:
            output += f"  {ip}\n"
        return output


class HexDumpAnalyzer(BaseAnalyzer):
    """十六进制转储分析器"""
    
    def get_name(self) -> str:
        return "内存布局分析"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        # 分析内存布局特征
        total_size = len(data)
        null_bytes = data.count(b'\x00')
        printable = sum(1 for b in data if 32 <= b <= 126)
        
        # 查找重复模式
        patterns = defaultdict(int)
        for i in range(0, len(data) - 4, 4):
            chunk = data[i:i+4]
            patterns[chunk] += 1
        
        top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_size': total_size,
            'null_bytes': null_bytes,
            'null_percentage': (null_bytes / total_size * 100) if total_size > 0 else 0,
            'printable_bytes': printable,
            'printable_percentage': (printable / total_size * 100) if total_size > 0 else 0,
            'top_patterns': [(p.hex(), c) for p, c in top_patterns]
        }
    
    def format_result(self, result: Dict[str, Any]) -> str:
        output = f"内存布局统计:\n"
        output += f"  总大小: {result['total_size']} 字节\n"
        output += f"  空字节: {result['null_bytes']} ({result['null_percentage']:.2f}%)\n"
        output += f"  可打印字符: {result['printable_bytes']} ({result['printable_percentage']:.2f}%)\n\n"
        output += "最常见的4字节模式:\n"
        for pattern, count in result['top_patterns']:
            output += f"  {pattern}: {count}次\n"
        return output


class HTMLReportGenerator:
    """HTML报告生成器 - 可视化输出"""
    
    def __init__(self):
        self.analyzers = []
        self.results = {}
    
    def add_analyzer(self, analyzer: BaseAnalyzer):
        self.analyzers.append(analyzer)
    
    def analyze_all(self, data: bytes):
        """运行所有分析器"""
        for analyzer in self.analyzers:
            print(f"[*] 运行: {analyzer.get_name()}...")
            try:
                result = analyzer.analyze(data)
                self.results[analyzer.get_name()] = result
            except Exception as e:
                print(f"[!] {analyzer.get_name()} 失败: {e}")
                self.results[analyzer.get_name()] = {'error': str(e)}
    
    def generate_html(self, output_file: str):
        """生成HTML报告"""
        html_content = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MongoDB Memory Leak Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .nav {
            background: #f8f9fa;
            padding: 15px 30px;
            border-bottom: 2px solid #e9ecef;
            overflow-x: auto;
            white-space: nowrap;
        }
        .nav button {
            background: white;
            border: 2px solid #667eea;
            color: #667eea;
            padding: 10px 20px;
            margin-right: 10px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        .nav button:hover {
            background: #667eea;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(102,126,234,0.3);
        }
        .nav button.active {
            background: #667eea;
            color: white;
        }
        .content {
            padding: 30px;
        }
        .section {
            display: none;
        }
        .section.active {
            display: block;
            animation: fadeIn 0.5s;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .card {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin-top: 0;
            color: #667eea;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 10px rgba(102,126,234,0.3);
        }
        .stat-box h3 {
            margin: 0;
            font-size: 2em;
        }
        .stat-box p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .finding {
            background: white;
            border: 1px solid #e9ecef;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .finding .offset {
            color: #6c757d;
            font-weight: bold;
        }
        .finding .value {
            color: #28a745;
        }
        .credential {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .credential strong {
            color: #856404;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }
        table td {
            padding: 10px;
            border-bottom: 1px solid #e9ecef;
        }
        table tr:hover {
            background: #f8f9fa;
        }
        .warning {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
            color: #721c24;
        }
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border: 1px solid #e9ecef;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            background: #667eea;
            color: white;
            border-radius: 3px;
            font-size: 0.85em;
            margin-right: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 MongoDB Memory Leak Analysis Report</h1>
            <p>CVE-2025-14847 Memory Dump Analysis - Generated by mongobleed analyzer</p>
        </div>
        
        <div class="nav">
"""
        
        # 生成导航按钮
        for i, (name, _) in enumerate(self.results.items()):
            active = "active" if i == 0 else ""
            html_content += f'            <button class="nav-btn {active}" onclick="showSection(\'{name}\')">{name}</button>\n'
        
        html_content += """        </div>
        
        <div class="content">
"""
        
        # 生成各个分析器的结果部分
        for i, (name, result) in enumerate(self.results.items()):
            active = "active" if i == 0 else ""
            html_content += f'            <div class="section {active}" id="{name}">\n'
            html_content += f'                <h2>{name}</h2>\n'
            
            if 'error' in result:
                html_content += f'                <div class="warning">错误: {html_escape(result["error"])}</div>\n'
            else:
                html_content += self._format_result_html(name, result)
            
            html_content += '            </div>\n'
        
        html_content += """        </div>
    </div>
    
    <script>
        function showSection(sectionName) {
            // 隐藏所有section
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            
            // 显示选中的section
            document.getElementById(sectionName).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML报告已生成: {output_file}")
    
    def _format_result_html(self, name: str, result: Dict[str, Any]) -> str:
        """根据不同的分析器格式化HTML输出"""
        html = ""
        
        if name == "内存布局分析":
            html += '<div class="stats">\n'
            html += f'<div class="stat-box"><h3>{result["total_size"]}</h3><p>总字节数</p></div>\n'
            html += f'<div class="stat-box"><h3>{result["null_percentage"]:.1f}%</h3><p>空字节比例</p></div>\n'
            html += f'<div class="stat-box"><h3>{result["printable_percentage"]:.1f}%</h3><p>可打印字符</p></div>\n'
            html += '</div>\n'
            
            if result.get('top_patterns'):
                html += '<div class="card"><h3>最常见的4字节模式</h3><table>\n'
                html += '<tr><th>模式</th><th>出现次数</th></tr>\n'
                for pattern, count in result['top_patterns']:
                    html += f'<tr><td><code>{html_escape(pattern)}</code></td><td>{count}</td></tr>\n'
                html += '</table></div>\n'
        
        elif name == "凭证搜索":
            for category, items in result.items():
                if items:
                    html += f'<div class="card"><h3>{category.upper()} <span class="badge">{len(items)}</span></h3>\n'
                    for item in items[:50]:
                        html += f'<div class="credential">\n'
                        html += f'<strong>偏移 {item["offset"]:06d}:</strong> '
                        html += f'<code>{html_escape(item["value"])}</code>\n'
                        html += '</div>\n'
                    html += '</div>\n'
        
        elif name == "BSON字段分析":
            html += '<div class="stats">\n'
            html += f'<div class="stat-box"><h3>{result.get("total_fields", 0)}</h3><p>字段总数</p></div>\n'
            html += f'<div class="stat-box"><h3>{result.get("unique_fields", 0)}</h3><p>唯一字段</p></div>\n'
            html += '</div>\n'
            
            if result.get('top_fields'):
                html += '<div class="card"><h3>最常见的字段名</h3><table>\n'
                html += '<tr><th>字段名</th><th>出现次数</th></tr>\n'
                for name, count in result['top_fields'][:30]:
                    html += f'<tr><td><code>{html_escape(name)}</code></td><td>{count}</td></tr>\n'
                html += '</table></div>\n'
        
        elif name == "字符串提取":
            html += f'<div class="stats"><div class="stat-box"><h3>{result.get("total_strings", 0)}</h3><p>找到的字符串</p></div></div>\n'
            if result.get('findings'):
                html += '<div class="card"><h3>提取的字符串（前100个）</h3>\n'
                for item in result['findings'][:100]:
                    html += f'<div class="finding">\n'
                    html += f'<span class="offset">[{item["offset"]:06d}]</span> '
                    html += f'<span class="value">{html_escape(item["content"])}</span>\n'
                    html += '</div>\n'
                html += '</div>\n'
        
        elif name == "JSON数据提取":
            if result.get('findings'):
                html += f'<div class="stats"><div class="stat-box"><h3>{len(result["findings"])}</h3><p>JSON对象</p></div></div>\n'
                html += '<div class="card"><h3>提取的JSON数据</h3>\n'
                for item in result['findings'][:20]:
                    html += f'<div class="finding">\n'
                    html += f'<strong>偏移 {item["offset"]:06d}:</strong><br>\n'
                    html += f'<pre>{html_escape(json.dumps(item["data"], indent=2, ensure_ascii=False))}</pre>\n'
                    html += '</div>\n'
                html += '</div>\n'
        
        elif name in ["邮箱地址提取", "IP地址提取"]:
            if result.get('findings'):
                html += f'<div class="stats"><div class="stat-box"><h3>{len(result["findings"])}</h3><p>找到的项目</p></div></div>\n'
                html += '<div class="card"><h3>提取的数据</h3>\n'
                for item in result['findings']:
                    html += f'<div class="finding">{html_escape(item)}</div>\n'
                html += '</div>\n'
        
        return html


def main():
    parser = argparse.ArgumentParser(
        description='MongoDB Memory Leak Data Analyzer - 类似于JDumpSpider的内存数据分析工具'
    )
    parser.add_argument('input', help='输入文件（leaked.bin）')
    parser.add_argument('--output-txt', default='analysis.txt', help='文本报告输出文件')
    parser.add_argument('--output-html', default='analysis.html', help='HTML报告输出文件')
    parser.add_argument('--format', choices=['txt', 'html', 'both'], default='both', 
                        help='输出格式')
    args = parser.parse_args()
    
    print("[*] MongoDB Memory Leak Analyzer")
    print(f"[*] 读取文件: {args.input}")
    
    try:
        with open(args.input, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[!] 错误: 文件不存在 {args.input}")
        print("[!] 请先运行 mongobleed.py 生成 leaked.bin 文件")
        return
    
    print(f"[*] 文件大小: {len(data)} 字节")
    
    # 创建报告生成器
    generator = HTMLReportGenerator()
    
    # 添加所有分析器（类似JDumpSpider的spider列表）
    analyzers = [
        HexDumpAnalyzer(),
        CredentialHunter(),
        BSONFieldAnalyzer(),
        StringExtractor(),
        JSONExtractor(),
        EmailExtractor(),
        IPAddressExtractor(),
    ]
    
    for analyzer in analyzers:
        generator.add_analyzer(analyzer)
    
    # 运行所有分析
    generator.analyze_all(data)
    
    # 生成输出
    if args.format in ['txt', 'both']:
        print(f"\n[*] 生成文本报告: {args.output_txt}")
        with open(args.output_txt, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("MongoDB Memory Leak Analysis Report\n")
            f.write("=" * 80 + "\n\n")
            
            for analyzer in analyzers:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"{analyzer.get_name()}\n")
                f.write("=" * 80 + "\n")
                result = generator.results.get(analyzer.get_name(), {})
                f.write(analyzer.format_result(result))
                f.write("\n")
    
    if args.format in ['html', 'both']:
        print(f"[*] 生成HTML报告: {args.output_html}")
        generator.generate_html(args.output_html)
    
    print("\n[+] 分析完成!")
    print(f"[+] 查看报告: {args.output_html if args.format in ['html', 'both'] else args.output_txt}")


if __name__ == '__main__':
    main()

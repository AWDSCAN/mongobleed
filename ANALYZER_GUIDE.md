# MongoDB Memory Leak Analyzer - 完整说明

## 概述

这个工具是参考 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 的设计理念开发的MongoDB内存泄露数据分析器。JDumpSpider用于分析Java堆转储，而本工具用于分析MongoDB CVE-2025-14847漏洞泄露的原始内存数据。

## 核心设计理念对比

### JDumpSpider 架构
```
JDumpSpider
├── ISpider (接口) - 定义分析器契约
├── IHeapHolder - 堆数据访问抽象
├── 具体Spider实现
│   ├── ExportAllString - 导出所有字符串
│   ├── UserPassSearcher01 - 搜索用户名密码
│   ├── PropertySource* - 提取配置属性
│   ├── DataSource* - 提取数据源配置
│   ├── ShiroKey - 提取Shiro密钥
│   └── ... (更多专用分析器)
└── HTML报告生成
```

### 本工具架构
```
MongoDB Leak Analyzer
├── BaseAnalyzer (基类) - 定义分析器接口
├── 直接处理bytes数据 - 类似IHeapHolder的功能
├── 具体Analyzer实现
│   ├── StringExtractor - 字符串提取 (类似ExportAllString)
│   ├── CredentialHunter - 凭证搜索 (类似UserPassSearcher01)
│   ├── BSONFieldAnalyzer - BSON字段分析 (MongoDB特定)
│   ├── JSONExtractor - JSON对象提取 (类似PropertySource*)
│   ├── EmailExtractor - 邮箱提取
│   ├── IPAddressExtractor - IP地址提取
│   └── HexDumpAnalyzer - 内存布局分析
└── HTMLReportGenerator - 可视化报告生成
```

## 使用场景

### 场景1: 快速测试（使用演示数据）

```bash
# 创建测试数据
python3 << 'EOF'
data = bytearray()
data.extend(b'username: admin\x00password: secret123\x00')
data.extend(b'api_key: sk-1234567890abcdef\x00')
data.extend(b'email: admin@example.com\x00')
with open('test.bin', 'wb') as f: f.write(data)
EOF

# 分析
./analyzer.py test.bin

# 查看结果
cat analysis.txt
$BROWSER analysis.html
```

### 场景2: 实际漏洞利用

```bash
# 1. 启动测试环境
docker-compose up -d

# 2. 运行漏洞利用
./mongobleed.py --host localhost --port 27017

# 3. 分析泄露数据
./analyzer.py leaked.bin

# 4. 查看报告
$BROWSER analysis.html
```

### 场景3: 完整演示

```bash
# 运行完整演示流程
./demo.sh
```

## 分析器详解

### 1. 内存布局分析 (HexDumpAnalyzer)
- **功能**: 分析内存的基本统计特征
- **输出**: 
  - 总字节数
  - 空字节比例
  - 可打印字符比例
  - 常见的4字节模式（用于识别内存对齐和重复数据）

### 2. 凭证搜索 (CredentialHunter)
类似于JDumpSpider的 UserPassSearcher01，但针对MongoDB环境优化。

**搜索模式**:
```python
patterns = {
    'passwords': [r'password["\s:=]+(.+)', ...],
    'usernames': [r'username["\s:=]+(.+)', ...],
    'api_keys': [r'api[_-]?key["\s:=]+([A-Za-z0-9_-]{16,})', ...],
    'tokens': [r'token["\s:=]+(.+)', ...],
    'aws_keys': [r'(AKIA[0-9A-Z]{16})', ...],
    'mongodb_uris': [r'mongodb://[^\s\x00]+', ...],
}
```

**输出示例**:
```
PASSWORDS:
  偏移 456: SuperSecret123!

API_KEYS:
  偏移 482: sk-1234567890abcdef1234567890abcdef

AWS_KEYS:
  偏移 618: AKIAIOSFODNN7EXAMPLE

MONGODB_URIS:
  偏移 579: mongodb://user:pass@localhost:27017/db
```

### 3. BSON字段分析 (BSONFieldAnalyzer)
MongoDB特有的分析器，利用CVE-2025-14847的特性。

**原理**: 
- 漏洞导致MongoDB从未初始化内存读取BSON字段名
- 字段名以null字节结尾
- 可以推断数据库架构

**输出示例**:
```
找到 32 个字段名（12 个唯一）:

出现频率最高的字段:
  5x  username
  5x  password
  5x  email
  5x  api_key
  5x  token
```

### 4. 字符串提取 (StringExtractor)
类似于JDumpSpider的 ExportAllString。

**功能**: 提取所有可打印ASCII字符串（最小长度4）

### 5. JSON数据提取 (JSONExtractor)
类似于JDumpSpider的 PropertySource* 系列。

**功能**: 识别并解析有效的JSON对象

**输出示例**:
```json
{
  "username": "admin",
  "role": "superadmin"
}
```

### 6. 邮箱地址提取 (EmailExtractor)
**正则**: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`

### 7. IP地址提取 (IPAddressExtractor)
**正则**: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
**验证**: 确保每段在0-255范围内

## HTML报告特性

### 界面设计
- 🎨 现代渐变色设计（紫色主题）
- 📱 响应式布局
- 🔄 交互式标签页切换
- 📊 统计数据可视化

### 报告结构
```
┌────────────────────────────────────────┐
│  MongoDB Memory Leak Analysis Report  │  ← 标题栏
├────────────────────────────────────────┤
│ [内存] [凭证] [BSON] [字符串] [JSON]   │  ← 导航标签
├────────────────────────────────────────┤
│                                        │
│  ┌──────────┐ ┌──────────┐           │
│  │ 总字节数  │ │ 空字节率  │  ← 统计卡片
│  └──────────┘ └──────────┘           │
│                                        │
│  ┌────────────────────────────────┐   │
│  │ 详细分析结果                    │  ← 内容区域
│  │ • 发现的凭证                    │
│  │ • 提取的字段                    │
│  │ • ...                           │
│  └────────────────────────────────┘   │
│                                        │
└────────────────────────────────────────┘
```

## 扩展开发

### 添加自定义分析器

参考JDumpSpider的插件机制：

```python
class CustomPatternAnalyzer(BaseAnalyzer):
    """自定义模式分析器"""
    
    def get_name(self) -> str:
        return "自定义分析"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        findings = []
        
        # 实现你的分析逻辑
        pattern = rb'your_pattern_here'
        for match in re.finditer(pattern, data):
            findings.append({
                'offset': match.start(),
                'data': match.group().decode('utf-8', errors='ignore')
            })
        
        return {'findings': findings}
    
    def format_result(self, result: Dict[str, Any]) -> str:
        if not result.get('findings'):
            return "未发现匹配数据\n"
        
        output = "找到的匹配项:\n"
        for item in result['findings']:
            output += f"  偏移 {item['offset']:6d}: {item['data']}\n"
        return output
```

### 注册分析器

在 `main()` 函数中添加：

```python
analyzers = [
    HexDumpAnalyzer(),
    CredentialHunter(),
    # ... 其他分析器
    CustomPatternAnalyzer(),  # 添加你的分析器
]
```

## 性能优化

### 大文件处理

对于大型内存转储（>100MB）：

```python
# 修改分析器限制结果数量
def analyze(self, data: bytes) -> Dict[str, Any]:
    findings = []
    max_findings = 1000  # 限制发现数量
    
    for match in re.finditer(pattern, data):
        if len(findings) >= max_findings:
            break
        findings.append(...)
    
    return {'findings': findings, 'truncated': len(findings) >= max_findings}
```

### 内存优化

```python
# 使用生成器处理大文件
def analyze_stream(self, data: bytes, chunk_size: int = 1024*1024):
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        yield self.analyze_chunk(chunk)
```

## 与JDumpSpider的对比

| 特性 | JDumpSpider | MongoDB Leak Analyzer |
|------|-------------|----------------------|
| **数据源** | Java堆转储(.hprof) | 原始内存字节流 |
| **数据结构** | 完整对象图 | 未结构化字节 |
| **查询能力** | OQL (对象查询语言) | 正则表达式匹配 |
| **类型感知** | ✅ 完全类型感知 | ❌ 基于模式匹配 |
| **分析精度** | 高 (知道对象边界) | 中 (推断数据边界) |
| **扩展性** | ✅ 插件架构 | ✅ 插件架构 |
| **可视化** | ✅ HTML报告 | ✅ HTML报告 |
| **适用场景** | Java应用分析 | 内存泄露分析 |

## 实际案例

### 案例1: 发现数据库凭证

```
INPUT: leaked.bin (从生产环境MongoDB泄露)

分析结果:
  MONGODB_URIS:
    mongodb://prod_user:P@ssw0rd!@mongodb.internal.company.com:27017/production

  PASSWORDS:
    数据库密码: P@ssw0rd!
    管理员密码: AdminSecret123

影响: 发现生产数据库凭证，立即修改密码
```

### 案例2: 推断数据库架构

```
BSON字段分析结果:
  users.username
  users.password_hash
  users.email
  users.created_at
  orders.order_id
  orders.user_id
  orders.total_amount
  payments.card_number
  payments.cvv

洞察: 
  - 存在用户表、订单表、支付表
  - 支付信息字段可能存储敏感信息
  - 建议审查数据加密策略
```

### 案例3: 发现API密钥

```
API_KEYS:
  sk-1234567890abcdef... (Stripe API密钥)
  AIzaSyD... (Google API密钥)
  
AWS_KEYS:
  AKIAIOSFODNN7EXAMPLE

操作建议:
  1. 立即轮换所有泄露的密钥
  2. 审计API密钥使用日志
  3. 启用密钥轮换策略
```

## 最佳实践

### 1. 数据收集
```bash
# 使用不同的偏移范围多次扫描
./mongobleed.py --min-offset 20 --max-offset 1000 --output pass1.bin
./mongobleed.py --min-offset 1000 --max-offset 10000 --output pass2.bin
./mongobleed.py --min-offset 10000 --max-offset 50000 --output pass3.bin
```

### 2. 合并分析
```bash
# 合并多次扫描的结果
cat pass*.bin > combined.bin

# 分析合并数据
./analyzer.py combined.bin
```

### 3. 交叉验证
```bash
# 同时生成文本和HTML报告
./analyzer.py leaked.bin --format both

# 文本报告适合grep搜索
grep -i "password" analysis.txt

# HTML报告适合交互式查看
```

### 4. 安全处理
```bash
# 分析后立即加密敏感数据
gpg -c leaked.bin
gpg -c analysis.txt
rm leaked.bin analysis.txt

# 使用完毕后安全删除
shred -vfz leaked.bin.gpg analysis.txt.gpg
```

## 故障排查

### 问题1: 未发现任何数据
```
原因: 
  - 目标MongoDB可能已修补
  - 偏移范围不正确
  - 内存中无敏感数据

解决:
  # 扩大扫描范围
  ./mongobleed.py --max-offset 100000
```

### 问题2: 分析器报错
```
错误: AttributeError, KeyError等

解决:
  # 检查输入文件
  file leaked.bin
  hexdump -C leaked.bin | head
  
  # 重新生成数据
  rm leaked.bin
  ./mongobleed.py --host target
```

### 问题3: HTML报告过大
```
原因: 发现大量数据

解决:
  # 修改analyzer.py中的限制
  findings = findings[:100]  # 限制每类结果数量
```

## 参考资源

- [JDumpSpider GitHub](https://github.com/whwlsfb/JDumpSpider) - 灵感来源
- [CVE-2025-14847](https://nvd.nist.gov/) - MongoDB漏洞详情
- [BSON规范](http://bsonspec.org/) - 理解BSON格式
- [mongobleed.py](./mongobleed.py) - 漏洞利用脚本

## 贡献指南

欢迎贡献新的分析器！请确保：

1. 继承 `BaseAnalyzer` 基类
2. 实现所有必需方法
3. 添加详细的文档字符串
4. 提供使用示例

## 许可证

本工具仅用于安全研究和授权渗透测试。未经授权使用可能违法。

---

**注意**: 这是一个安全研究工具。请负责任地使用，并遵守所有适用的法律法规。

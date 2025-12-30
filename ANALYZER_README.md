# MongoDB Memory Leak Analyzer 使用说明

这是一个用于分析MongoDB内存泄露数据的可视化工具，灵感来自于 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 的架构设计。

## 功能特性

参考JDumpSpider的设计理念，本工具采用了插件化的分析器架构：

### 核心分析器

1. **内存布局分析** - 分析内存的基本特征和模式
2. **凭证搜索** - 搜索密码、API密钥、令牌等敏感信息
3. **BSON字段分析** - 提取和统计MongoDB BSON字段名
4. **字符串提取** - 提取所有可读字符串
5. **JSON数据提取** - 识别和解析JSON对象
6. **邮箱地址提取** - 提取电子邮件地址
7. **IP地址提取** - 提取IP地址

### 类比 JDumpSpider

| JDumpSpider 组件 | Analyzer 对应组件 | 说明 |
|-----------------|------------------|------|
| `ISpider` 接口 | `BaseAnalyzer` 类 | 分析器基类接口 |
| `IHeapHolder` | 直接操作bytes数据 | 数据访问层 |
| `ExportAllString` | `StringExtractor` | 字符串提取 |
| `UserPassSearcher01` | `CredentialHunter` | 凭证搜索 |
| `PropertySource*` | `JSONExtractor` | 结构化数据提取 |
| HTML输出 | `HTMLReportGenerator` | 可视化报告生成 |

## 使用方法

### 1. 首先运行 mongobleed.py 获取内存泄露数据

```bash
# 启动MongoDB测试环境
docker-compose up -d

# 运行漏洞利用脚本
./mongobleed.py --host localhost --port 27017 --output leaked.bin
```

### 2. 分析泄露的数据

```bash
# 生成HTML和文本报告（默认）
./analyzer.py leaked.bin

# 只生成HTML报告
./analyzer.py leaked.bin --format html --output-html report.html

# 只生成文本报告
./analyzer.py leaked.bin --format txt --output-txt report.txt

# 自定义输出文件名
./analyzer.py leaked.bin --output-txt my_analysis.txt --output-html my_report.html
```

### 3. 查看分析结果

**HTML报告**（推荐）：
```bash
# 在容器内使用浏览器打开
$BROWSER analysis.html

# 或者复制到本地查看
```

**文本报告**：
```bash
cat analysis.txt
```

## 输出示例

### HTML报告特性

- 🎨 精美的渐变色界面设计
- 📊 交互式标签页切换
- 📈 统计数据可视化展示
- 🔍 语法高亮的代码显示
- 📱 响应式设计，支持移动端

### 文本报告示例

```
================================================================================
内存布局分析
================================================================================
内存布局统计:
  总大小: 45678 字节
  空字节: 12345 (27.02%)
  可打印字符: 23456 (51.34%)

最常见的4字节模式:
  00000000: 234次
  20202020: 156次
  ...

================================================================================
凭证搜索
================================================================================

PASSWORDS:
------------------------------------------------------------
  偏移   1234: mypassword123
  偏移   5678: secretpass
  ...

API_KEYS:
------------------------------------------------------------
  偏移   9012: AIzaSyD_example_key_12345
  ...
```

## 架构设计

```
analyzer.py
├── BaseAnalyzer (基类)
│   ├── get_name()      - 获取分析器名称
│   ├── analyze()       - 执行分析
│   └── format_result() - 格式化输出
│
├── 具体分析器实现
│   ├── StringExtractor
│   ├── CredentialHunter
│   ├── BSONFieldAnalyzer
│   ├── JSONExtractor
│   ├── EmailExtractor
│   ├── IPAddressExtractor
│   └── HexDumpAnalyzer
│
└── HTMLReportGenerator
    ├── add_analyzer()    - 注册分析器
    ├── analyze_all()     - 运行所有分析
    └── generate_html()   - 生成HTML报告
```

### 扩展自定义分析器

参考JDumpSpider的插件机制，您可以轻松添加自定义分析器：

```python
class CustomAnalyzer(BaseAnalyzer):
    def get_name(self) -> str:
        return "自定义分析器"
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        # 实现您的分析逻辑
        findings = []
        # ... 分析代码 ...
        return {'findings': findings}
    
    def format_result(self, result: Dict[str, Any]) -> str:
        # 格式化输出
        return "分析结果..."

# 添加到主程序
generator.add_analyzer(CustomAnalyzer())
```

## 技术细节

### 凭证搜索模式

工具会搜索以下模式：
- 密码: `password`, `passwd`, `pwd`
- 用户名: `username`, `user`, `login`
- API密钥: `api_key`, `apikey`
- 令牌: `token`, `auth`
- AWS密钥: `AKIA[0-9A-Z]{16}`
- MongoDB连接串: `mongodb://`, `mongodb+srv://`

### BSON字段识别

通过正则表达式识别null结尾的字符串，这些通常是MongoDB BSON文档的字段名。

### JSON提取

查找形如 `{...}` 的模式并尝试解析为有效的JSON对象。

## 安全建议

⚠️ **警告**: 此工具用于安全研究和授权测试。泄露的内存数据可能包含敏感信息：

- 不要在生产环境未经授权运行
- 妥善保管生成的报告文件
- 分析完成后安全删除敏感数据
- 遵守相关法律法规

## 依赖项

- Python 3.6+
- 无需额外依赖（仅使用标准库）

## 对比 JDumpSpider

### 相似之处
- ✅ 插件化架构设计
- ✅ 多种分析器支持
- ✅ HTML可视化报告
- ✅ 结构化数据提取

### 不同之处
| 特性 | JDumpSpider | Analyzer |
|------|-------------|----------|
| 目标 | Java堆转储(.hprof) | 原始内存数据 |
| 数据结构 | 完整的对象图 | 字节流 |
| 分析精度 | 类型感知 | 模式匹配 |
| 查询能力 | OQL支持 | 正则表达式 |

## 示例场景

### 场景1: 查找数据库凭证

```bash
./analyzer.py leaked.bin --format html
# 打开 analysis.html，查看"凭证搜索"标签页
```

### 场景2: 分析数据库结构

```bash
./analyzer.py leaked.bin
# 查看"BSON字段分析"了解数据库架构
```

### 场景3: 提取所有敏感信息

```bash
./analyzer.py leaked.bin --format both
# 同时生成HTML和文本报告进行交叉分析
```

## 性能建议

- 大文件（>100MB）分析可能需要几分钟
- HTML报告大小取决于发现的数据量
- 可以修改分析器中的限制参数来控制输出大小

## 贡献

欢迎参考JDumpSpider的插件架构添加新的分析器！

## 参考

- [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) - Java堆转储分析工具
- [CVE-2025-14847](https://nvd.nist.gov/) - MongoDB内存泄露漏洞
- [mongobleed.py](./mongobleed.py) - 漏洞利用脚本

## 许可证

本工具仅用于安全研究和教育目的。

# MongoDB Memory Leak Analyzer - 快速参考

## 一键命令

```bash
# 完整演示
./demo.sh

# 快速分析
./mongobleed.py && ./analyzer.py leaked.bin

# 仅生成HTML
./analyzer.py leaked.bin --format html

# 深度扫描
./mongobleed.py --max-offset 50000 && ./analyzer.py leaked.bin
```

## 分析器速查

| 分析器 | JDumpSpider对应 | 功能 |
|--------|----------------|------|
| HexDumpAnalyzer | - | 内存统计 |
| CredentialHunter | UserPassSearcher01 | 凭证搜索 |
| BSONFieldAnalyzer | - | MongoDB字段 |
| StringExtractor | ExportAllString | 字符串提取 |
| JSONExtractor | PropertySource* | JSON提取 |
| EmailExtractor | - | 邮箱提取 |
| IPAddressExtractor | - | IP提取 |

## 常见模式

### 密码
- `password["\s:=]+(.+)`
- `passwd["\s:=]+(.+)`
- `pwd["\s:=]+(.+)`

### API密钥
- `api[_-]?key["\s:=]+([A-Za-z0-9_-]{16,})`
- `AKIA[0-9A-Z]{16}` (AWS)

### MongoDB URI
- `mongodb://[^\s\x00]+`
- `mongodb\+srv://[^\s\x00]+`

## 文件说明

```
mongobleed/
├── mongobleed.py          # 漏洞利用
├── analyzer.py            # 分析工具 ⭐
├── demo.sh               # 完整演示
├── README.md             # 项目主文档
├── ANALYZER_README.md    # 分析器使用说明
└── ANALYZER_GUIDE.md     # 详细指南
```

## 输出文件

```
leaked.bin         # 原始泄露数据
analysis.txt       # 文本报告
analysis.html      # HTML报告 ⭐ (推荐)
```

## 核心API

```python
# 创建分析器
class MyAnalyzer(BaseAnalyzer):
    def get_name(self): return "名称"
    def analyze(self, data): return {'findings': [...]}
    def format_result(self, result): return "文本输出"

# 注册分析器
generator = HTMLReportGenerator()
generator.add_analyzer(MyAnalyzer())
generator.analyze_all(data)
generator.generate_html('report.html')
```

## 设计对比

```
JDumpSpider               →  MongoDB Leak Analyzer
─────────────────────────────────────────────────────
ISpider                   →  BaseAnalyzer
IHeapHolder               →  bytes直接操作
ExportAllString           →  StringExtractor
UserPassSearcher01        →  CredentialHunter
PropertySource*           →  JSONExtractor
HeapFactory               →  open(file, 'rb')
OQLEngine                 →  re.finditer()
HTML报告                   →  HTML报告
```

## 快速测试

```bash
# 创建测试数据
echo -ne 'password: test123\x00api_key: sk-abc\x00' > test.bin

# 分析
./analyzer.py test.bin

# 查看
cat analysis.txt | grep -A5 "凭证搜索"
```

## 性能建议

| 文件大小 | 时间 | 建议 |
|---------|------|------|
| < 1MB   | <1s  | 默认设置 |
| 1-10MB  | 1-5s | 默认设置 |
| 10-100MB | 5-30s | 限制结果数 |
| > 100MB | >30s | 分块处理 |

## 常见问题

**Q: 为什么模仿JDumpSpider？**
A: JDumpSpider的插件化架构非常适合多样化数据分析场景。

**Q: 与JDumpSpider的主要区别？**
A: JDumpSpider处理结构化的Java堆，我们处理非结构化的原始内存。

**Q: 如何添加新分析器？**
A: 继承`BaseAnalyzer`，实现3个方法，在main()中注册。

**Q: HTML报告如何查看？**
A: 容器内: `$BROWSER analysis.html` 或复制到本地查看。

## 架构精髓

```
插件化设计 (从JDumpSpider学习)
├── 接口定义 (BaseAnalyzer)
├── 具体实现 (各种Analyzer)
├── 数据访问 (bytes操作)
└── 结果呈现 (HTML/Text)

优点:
✅ 易扩展 - 添加新分析器很简单
✅ 解耦合 - 各分析器独立工作
✅ 可复用 - 分析逻辑可单独使用
✅ 可测试 - 每个组件可独立测试
```

## 实战技巧

```bash
# 1. 多次扫描覆盖不同内存区域
for i in {0..10}; do
  ./mongobleed.py --min-offset $((i*5000)) --max-offset $(((i+1)*5000)) -o scan_$i.bin
done

# 2. 合并并去重
cat scan_*.bin | sort -u > all.bin

# 3. 深度分析
./analyzer.py all.bin --format both

# 4. 提取特定信息
grep -o "password.*" analysis.txt > passwords.txt
grep -o "mongodb://.*" analysis.txt > connections.txt
```

## 相关资源

- 📚 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider)
- 🔒 [CVE-2025-14847](https://nvd.nist.gov/)
- 📖 [BSON Spec](http://bsonspec.org/)
- 🐍 [Python正则](https://docs.python.org/3/library/re.html)

---

💡 **提示**: 这个工具的设计理念完全借鉴了JDumpSpider的插件架构，只是应用场景从Java堆分析变成了原始内存分析。

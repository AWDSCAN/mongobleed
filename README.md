# mongobleed

**CVE-2025-14847** - MongoDB 未授权内存泄露漏洞利用工具

MongoDB zlib 解压缩漏洞的概念验证工具，允许未授权攻击者泄露服务器敏感内存数据。

## 漏洞简介

MongoDB 的 zlib 消息解压缩存在缺陷，返回分配的缓冲区大小而非实际解压后的数据长度。攻击者利用此漏洞可以读取未初始化的内存：

1. 发送带有虚假 `uncompressedSize` 的压缩消息
2. MongoDB 根据攻击者声明的大小分配大缓冲区
3. zlib 将实际数据解压到缓冲区开头
4. 漏洞导致 MongoDB 将整个缓冲区视为有效数据
5. BSON 解析从未初始化内存读取"字段名"直到遇到空字节

## 受影响版本

| 版本 | 受影响范围 | 修复版本 |
|------|-----------|---------|
| 8.2.x | 8.2.0 - 8.2.2 | 8.2.3 |
| 8.0.x | 8.0.0 - 8.0.16 | 8.0.17 |
| 7.0.x | 7.0.0 - 7.0.27 | 7.0.28 |
| 6.0.x | 6.0.0 - 6.0.26 | 6.0.27 |
| 5.0.x | 5.0.0 - 5.0.31 | 5.0.32 |

## 快速开始

```bash
# 基础扫描
python3 mongobleed.py --host <目标IP>

# 深度扫描（更多数据）
python3 mongobleed.py --host <目标IP> --max-offset 50000

# 分析泄露数据
python3 analyzer.py leaked.bin

# 完整演示
./demo.sh
```

## 使用说明

### 1. 内存泄露利用 (mongobleed.py)

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | localhost | 目标 MongoDB 主机 |
| `--port` | 27017 | 目标端口 |
| `--min-offset` | 20 | 最小文档长度 |
| `--max-offset` | 8192 | 最大文档长度 |
| `--output` | leaked.bin | 输出文件 |

### 2. 内存数据分析 (analyzer.py)

参考 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 的设计理念，采用插件化架构分析内存数据：

```bash
# 生成文本和HTML报告
python3 analyzer.py leaked.bin

# 仅生成HTML
python3 analyzer.py leaked.bin --format html

# 自定义输出文件
python3 analyzer.py leaked.bin --output-html report.html
```

**分析器模块** (7个插件)：

| 模块 | 功能 | 对应 JDumpSpider |
|------|------|-----------------|
| 🔍 **内存布局分析** | 统计分析、模式识别 | - |
| 🔐 **凭证搜索** | 密码、API密钥、令牌、AWS密钥 | UserPassSearcher01 |
| 📋 **BSON字段分析** | MongoDB字段名、数据库架构 | - |
| 📝 **字符串提取** | 可打印字符串 | ExportAllString |
| 📦 **JSON数据提取** | 有效JSON对象 | PropertySource* |
| 📧 **邮箱地址提取** | 电子邮件地址 | - |
| 🌐 **IP地址提取** | IP地址信息 | - |

**报告输出**：
- `analysis.txt` - 详细文本报告
- `analysis.html` - 交互式可视化HTML报告（推荐）

详细文档：[ANALYZER_README.md](ANALYZER_README.md) | [ANALYZER_GUIDE.md](ANALYZER_GUIDE.md) | [QUICK_REFERENCE.md](QUICK_REFERENCE.md)

## 测试环境

使用 Docker Compose 快速启动易受攻击的 MongoDB：

```bash
docker-compose up -d
python3 mongobleed.py --host localhost
python3 analyzer.py leaked.bin
```

## 工作原理

通过构造带有虚假长度字段的 BSON 文档，当服务器解析时会从未初始化内存读取字段名直到遇到空字节。不同偏移量的探测可泄露不同内存区域。

**可能泄露的数据**：
- MongoDB 内部日志和状态
- WiredTiger 存储引擎配置
- 系统 `/proc` 数据（meminfo、网络统计）
- 用户凭证和 API 密钥
- 数据库连接字符串
- 敏感业务数据

## 输出示例

```
[*] mongobleed - CVE-2025-14847 MongoDB 内存泄露
[*] 作者: Joe Desimone - x.com/dez_
[*] 目标: 192.168.1.100:27017
[*] 扫描偏移量 20-8192

[+] offset=  197 len=  19: istory store in SLS
[+] offset=  282 len=  21: transaction commit
[+] offset=  388 len=  54: skipped an update or updates

[*] 总泄露: 189 字节
[*] 唯一片段: 23
[*] 保存至: leaked.bin

[*] 运行分析器...
[+] 生成报告: analysis.html (可视化)
[+] 生成报告: analysis.txt (文本)
```

## 架构设计

```
mongobleed 工具链
├── mongobleed.py          - CVE-2025-14847 漏洞利用
├── analyzer.py            - 内存数据分析（插件化架构）
│   ├── BaseAnalyzer          (类似 ISpider 接口)
│   ├── HexDumpAnalyzer       内存布局
│   ├── CredentialHunter      凭证搜索
│   ├── BSONFieldAnalyzer     BSON字段
│   ├── StringExtractor       字符串提取
│   ├── JSONExtractor         JSON解析
│   ├── EmailExtractor        邮箱提取
│   └── IPAddressExtractor    IP提取
├── demo.sh                - 完整演示脚本
└── docker-compose.yml     - 测试环境
```

**设计灵感**：完全借鉴 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 的插件化架构，将其从 Java 堆分析扩展到原始内存字节流分析。

## 参考资料

- [OX Security 安全公告](https://www.ox.security/blog/attackers-could-exploit-zlib-to-exfiltrate-data-cve-2025-14847/)
- [MongoDB 修复提交](https://github.com/mongodb/mongo/commit/505b660a14698bd2b5233bd94da3917b585c5728)
- [JDumpSpider - Java堆分析工具](https://github.com/whwlsfb/JDumpSpider)

## 作者

Joe Desimone - [x.com/dez_](https://x.com/dez_)

## 免责声明

此工具仅用于授权安全测试。未经授权访问计算机系统是非法行为。


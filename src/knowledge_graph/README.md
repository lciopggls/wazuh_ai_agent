# 知识图谱模块

从 CTI 报告自动生成 MITRE ATT&CK 知识图谱。

## 前置条件

**1. 同步依赖**

```powershell
cd D:\Learn\wazuh0\agit\wazuh_ai_agent
uv sync
```

**2. 下载 NLP 模型数据**

```powershell
uv run python -m spacy download en_core_web_sm
```

**3. 安装 NLTK 分词数据 (punkt)**

自动下载可能因网络限制失败，推荐手动安装：

```powershell
# 1. 下载 punkt.zip（浏览器或 Invoke-WebRequest）
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nltk/nltk_data/gh-pages/packages/tokenizers/punkt.zip" -OutFile "$env:USERPROFILE\punkt.zip"

# 2. 解压到 NLTK 数据目录
Expand-Archive "$env:USERPROFILE\punkt.zip" -DestinationPath "$env:APPDATA\nltk_data\tokenizers\punkt" -Force

# 3. 验证(命令无报错即表示 NLTK 能找到 punkt 数据)
uv run python -c "import nltk; nltk.data.find('tokenizers/punkt')"
```

> 如果 GitHub 被墙，用镜像：`https://ghproxy.com/https://github.com/nltk/nltk_data/raw/gh-pages/packages/tokenizers/punkt.zip`



## 目录结构

```
src/knowledge_graph/
├── input/                   ← ★ 用户放入 CTI 报告
├── output/                  ← ★ HTML 知识图谱输出
├── data/                    ← 流水线中间产物（自动管理）
│   ├── 1_rewrite/
│   ├── 2_extract/
│   ├── 3_label/
│   ├── 4_sort/
│   └── vis_cache/
├── stages/                  ← 流水线阶段脚本
├── template_files/          ← Prompt 模板资源
├── AttacKG_Run.py           ← 入口脚本
├── template.py              ← Prompt 构建引擎
├── config.py                ← LLM 配置
└── visualization.py         ← 图谱可视化
```



## 使用规范

1. **输入**：将 CTI 报告放入 `input/` 目录
2. **运行**：执行入口脚本
3. **输出**：在 `output/` 目录查看 HTML 图谱

```powershell
cd D:\Learn\wazuh0\agit\wazuh_ai_agent

# 1. 将报告放入 input/
#    cp your_report.txt src/knowledge_graph/input/

# 2. 运行
uv run python src\knowledge_graph\AttacKG_Run.py

# 3. 浏览器打开 output/ 下的 .html 文件
```



## 支持的文件格式

| 格式 | 编码 | 要求 |
|---|---|---|
| `.txt` | UTF-8 | 纯文本 CTI 报告 |
| `.md` | UTF-8 | Markdown 格式报告，支持标题、列表、代码块 |
| `.pdf` | — | 自动提取文本，无需手动转换 |

> 其他格式（如 `.docx`、`.html`）不支持，需手动转换为上述格式后放入 `input/`。



## 自定义参数

```powershell
# 默认：读取 input/，输出到 output/
uv run python src\knowledge_graph\AttacKG_Run.py

# 指定输入目录
uv run python src\knowledge_graph\AttacKG_Run.py path/to/reports

# 指定输入 + 输出子目录（如 output/group1/）
uv run python src\knowledge_graph\AttacKG_Run.py path/to/reports group1
```



## 断点续跑

已有输出的文件会被自动跳过。重新处理某份报告：

```powershell
Remove-Item "src\knowledge_graph\data\1_rewrite\报告名.json" -Force
Remove-Item "src\knowledge_graph\data\2_extract\报告名.json" -Force
Remove-Item "src\knowledge_graph\data\3_label\报告名.json" -Force
Remove-Item "src\knowledge_graph\data\4_sort\报告名.json" -Force
uv run python src\knowledge_graph\AttacKG_Run.py
```

# nsp2xci

在 macOS 上把 NSZ / NSP 转换为 XCI 或 NSP 格式。

## 环境要求

- Python 3.8+
- 有效的 `prod.keys`（从真机提取）

## 安装

```bash
cd nsp2xci
python3 -m venv venv
./venv/bin/pip install nsz
```

## 用法

```bash
./venv/bin/python3 nsp2xci.py [选项] 文件...
```

### 示例

```bash
# NSP → XCI
./venv/bin/python3 nsp2xci.py game.nsp

# NSZ → XCI（自动解压再转换）
./venv/bin/python3 nsp2xci.py game.nsz

# NSZ → NSP（只解压，不转 XCI）
./venv/bin/python3 nsp2xci.py game.nsz --nsp

# 批量转换，指定输出目录
./venv/bin/python3 nsp2xci.py *.nsz --output ~/xci/

# 指定 prod.keys 路径
./venv/bin/python3 nsp2xci.py game.nsz --keys ~/prod.keys
```

### 选项

| 选项 | 说明 |
|------|------|
| `--keys, -k` | prod.keys 路径（默认：项目目录或 `~/.switch/prod.keys`） |
| `--output, -o` | 输出目录（默认：与输入文件同目录） |
| `--nsp` | 输出 NSP 而不是 XCI（仅对 NSZ 输入有意义） |
| `--verbose, -v` | 显示详细信息 |

## prod.keys

把 `prod.keys` 放在项目目录下即可自动识别，无需额外指定。

NSP 转 XCI 不需要 keys，只有 NSZ 解压时才需要。

## 格式说明

| 格式 | 说明 |
|------|------|
| NSP | 数字版游戏（eShop 格式） |
| NSZ | NSP 的压缩版 |
| XCI | 卡带格式 |

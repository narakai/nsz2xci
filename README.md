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

**输出 XCI 一律需要 keys**（NSP、NSZ 都一样）：eShop 版的 NCA 带 titlekey 加密，转 XCI 时会用 ticket 里的
titlekey 写入 NCA 头的 key area 并清除 rights ID，使它和真卡带里的 NCA 一致，不再依赖 `.tik`。
数据部分不会被改动。

只有 **NSZ → NSP**（`--nsp`）时，keys 仅用于解压。普通 `.nsp` 加 `--nsp` 没有意义，会直接跳过。

### 安装时提示"无效的 NCA 签名"
正常现象。改过 NCA 头之后，任天堂的 RSA 签名自然对不上，重新签名需要任天堂私钥，谁都做不到。
带 sigpatches 的大气层环境下不影响安装和运行。

## 格式说明

| 格式 | 说明 |
|------|------|
| NSP | 数字版游戏（eShop 格式） |
| NSZ | NSP 的压缩版 |
| XCI | 卡带格式（输出的 XCI 只含 NCA，不含 ticket / cert） |

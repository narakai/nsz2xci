#!/usr/bin/env python3
"""
cheat_convert.py — Convert Switch cheat files to Eden Android format
Usage: python cheat_convert.py <cheat.txt> <BuildID> [--output DIR]
"""

import argparse
import re
import sys
from pathlib import Path


def convert(text):
    lines = text.splitlines()
    out = []
    for line in lines:
        stripped = line.strip()
        # Skip {comment} lines (author/title markers)
        if stripped.startswith('{') and stripped.endswith('}'):
            title = stripped[1:-1]
            out.append(f'[{title}]')
            continue
        # Convert [name] → [# name], but skip already-converted [# name] and bare section titles
        m = re.match(r'^\[([^#\]].+)\]$', stripped)
        if m:
            out.append(f'[# {m.group(1)}]')
            continue
        out.append(line)
    return '\n'.join(out).strip() + '\n'


def main():
    p = argparse.ArgumentParser(description='Convert cheat file to Eden Android format')
    p.add_argument('input', help='Input cheat .txt file')
    p.add_argument('build_id', help='Game Build ID (e.g. 53F407A2CFBF5202)')
    p.add_argument('--output', '-o', default='.', help='Output base directory (default: current dir)')
    args = p.parse_args()

    src = Path(args.input)
    if not src.exists():
        print(f'Error: file not found: {src}', file=sys.stderr)
        sys.exit(1)

    bid = args.build_id.upper()
    out_dir = Path(args.output) / bid / 'cheats'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f'{bid}.txt'

    converted = convert(src.read_text(encoding='utf-8'))
    out_file.write_text(converted, encoding='utf-8')

    print(f'Done: {out_file}')
    print(f'Import this folder in Eden Add-Ons: {out_dir.parent}')


if __name__ == '__main__':
    main()

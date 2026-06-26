#!/usr/bin/env python3
"""
nsp2xci — Convert NSP/NSZ to XCI on macOS
Usage: python nsp2xci.py game.nsz [--keys prod.keys] [--output dir]
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

MEDIA = 0x200          # media unit size (512 bytes)
XCI_HFS0_OFFSET = 0xF000  # physical offset where HFS0 root lives in XCI


# ─── PFS0 / NSP parsing ───────────────────────────────────────────────────────

def parse_pfs0(path):
    """Return list of {'name', 'offset', 'size'} for every file inside a PFS0/NSP."""
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic != b'PFS0':
            raise ValueError(f"Not a PFS0 file (got {magic!r}): {path}")
        num_files   = struct.unpack('<I', f.read(4))[0]
        str_tbl_sz  = struct.unpack('<I', f.read(4))[0]
        f.read(4)                           # reserved

        raw = []
        for _ in range(num_files):
            data_off = struct.unpack('<Q', f.read(8))[0]
            size     = struct.unpack('<Q', f.read(8))[0]
            name_off = struct.unpack('<I', f.read(4))[0]
            f.read(4)                       # reserved
            raw.append((data_off, size, name_off))

        str_table  = f.read(str_tbl_sz)
        header_end = f.tell()

    files = []
    for data_off, size, name_off in raw:
        end  = str_table.index(b'\x00', name_off)
        name = str_table[name_off:end].decode()
        files.append({'name': name, 'offset': header_end + data_off, 'size': size})
    return files


# ─── HFS0 builder ─────────────────────────────────────────────────────────────

def _align(n, boundary):
    return (n + boundary - 1) & ~(boundary - 1)


def build_hfs0_header(files):
    """
    Build an HFS0 directory header.
    files: list of {'name': str, 'size': int}
    Returns (header_bytes, data_area_start) where data_area_start is the offset
    within the resulting HFS0 blob where actual file data begins.
    """
    string_table = b''
    name_offsets = []
    for f in files:
        name_offsets.append(len(string_table))
        string_table += f['name'].encode() + b'\x00'

    raw_header_size = 0x10 + len(files) * 0x40 + len(string_table)
    header_size = _align(raw_header_size, MEDIA)  # pad to media boundary

    entries = b''
    data_cursor = 0
    for i, f in enumerate(files):
        entries += struct.pack('<QQ', data_cursor, f['size'])   # offset, size
        entries += struct.pack('<II', name_offsets[i], 0)       # name_off, hashed_region_size=0
        entries += b'\x00' * 8                                  # reserved
        entries += b'\x00' * 32                                 # SHA-256 (not hashed)
        data_cursor += f['size']

    header = b'HFS0'
    header += struct.pack('<III', len(files), len(string_table), 0)
    header += entries
    header += string_table
    header += b'\x00' * (header_size - len(header))
    return header, header_size


# ─── XCI writer ───────────────────────────────────────────────────────────────

def nsp_to_xci(nsp_path, out_path, verbose=False):
    nsp_path = Path(nsp_path)
    out_path = Path(out_path)

    files = parse_pfs0(nsp_path)
    if verbose:
        print(f"  {len(files)} files in NSP:")
        for f in files:
            print(f"    {f['name']}  {f['size']:,} B")

    # ── Build "secure" partition HFS0 (contains all NSP files) ──────────────
    secure_hdr, secure_data_start = build_hfs0_header(files)
    secure_data_size = sum(f['size'] for f in files)
    secure_total = len(secure_hdr) + secure_data_size

    # ── Build root HFS0 (contains only the "secure" sub-partition) ──────────
    root_hdr, root_data_start = build_hfs0_header([{'name': 'secure', 'size': secure_total}])

    # Physical layout inside XCI:
    #   XCI_HFS0_OFFSET              : root HFS0 header
    #   XCI_HFS0_OFFSET + root_data_start : secure partition start
    #   ↑ + len(secure_hdr)          : NCA data

    secure_phys_offset = XCI_HFS0_OFFSET + root_data_start  # abs. offset of "secure" HFS0

    # ── Build XCI header (0x000–0x1FF, trimmed-XCI layout) ──────────────────
    hfs0_offset_media   = XCI_HFS0_OFFSET // MEDIA          # 0x78
    secure_offset_media = secure_phys_offset // MEDIA

    total_size  = XCI_HFS0_OFFSET + root_data_start + secure_total
    valid_end   = _align(total_size, MEDIA) // MEDIA

    # SHA-256 of root HFS0 header bytes
    hfs0_hash = hashlib.sha256(root_hdr).digest()

    hdr  = b'\x00' * 0x100                              # RSA-2048 signature (zeroed)
    hdr += b'HEAD'                                       # magic
    hdr += struct.pack('<I', secure_offset_media)        # secureOffset
    hdr += struct.pack('<I', 0xFFFFFFFF)                 # backupOffset
    hdr += struct.pack('<BBBB', 0, 0xFA, 2, 0x83)       # titleKekIndex, gamecardSize, version, flags
    hdr += struct.pack('<Q', 0)                          # packageId
    hdr += struct.pack('<Q', valid_end)                  # validDataEndOffset
    hdr += b'\x00' * 0x10                               # gamecardInfo (encrypted, zeroed)
    hdr += struct.pack('<Q', hfs0_offset_media)          # hfs0Offset  (media units)
    hdr += struct.pack('<Q', len(root_hdr))              # hfs0HeaderSize
    hdr += hfs0_hash                                     # hfs0HeaderHash  (32 bytes)
    hdr += b'\x00' * 0x20                               # hfs0InitialDataHash
    hdr += struct.pack('<I', 1)                          # secureMode
    hdr += struct.pack('<I', 2)                          # titleKeyFlag
    hdr += struct.pack('<I', 0)                          # keyFlag
    hdr += struct.pack('<I', secure_offset_media)        # normalAreaEndOffset
    hdr += b'\x00' * (0x200 - len(hdr))                 # pad to 0x200

    assert len(hdr) == 0x200, f"XCI header is {len(hdr):#x} bytes, expected 0x200"

    # ── Write file ───────────────────────────────────────────────────────────
    CHUNK = 4 * 1024 * 1024

    with open(out_path, 'wb') as out:
        out.write(hdr)                                   # 0x000 – 0x1FF
        out.write(b'\x00' * (0x7000 - 0x200))           # 0x200 – 0x6FFF  reserved
        out.write(b'\x00' * 0x200)                       # 0x7000 – 0x71FF gamecard cert
        out.write(b'\x00' * (XCI_HFS0_OFFSET - 0x7200)) # 0x7200 – 0xEFFF reserved
        out.write(root_hdr)                              # 0xF000 root HFS0 header
        out.write(secure_hdr)                            # secure partition HFS0 header

        with open(nsp_path, 'rb') as nsp:
            for f in files:
                if verbose:
                    print(f"  writing {f['name']} …")
                nsp.seek(f['offset'])
                remaining = f['size']
                while remaining:
                    chunk = nsp.read(min(CHUNK, remaining))
                    out.write(chunk)
                    remaining -= len(chunk)

    size = os.path.getsize(out_path)
    print(f"  → {out_path.name}  ({size:,} bytes)")


# ─── NSZ decompression ────────────────────────────────────────────────────────

def _nsz_bin():
    """Path to the nsz binary in our venv."""
    return Path(__file__).parent / 'venv' / 'bin' / 'nsz'


def _setup_keys(keys_path):
    """
    Ensure prod.keys exists at ~/.switch/prod.keys (required by nsz).
    Returns True if we created the file (caller should delete it afterwards).
    """
    switch_dir = Path.home() / '.switch'
    switch_dir.mkdir(parents=True, exist_ok=True)
    target = switch_dir / 'prod.keys'
    if target.exists():
        return False          # already there, leave it
    shutil.copy2(keys_path, target)
    return True               # we created it


def decompress_nsz(nsz_path, work_dir, keys_path):
    """Decompress NSZ → NSP using nsz CLI. Returns Path to the resulting NSP."""
    nsz_path  = Path(nsz_path)
    work_dir  = Path(work_dir)
    keys_path = Path(keys_path)

    created = _setup_keys(keys_path)
    try:
        result = subprocess.run(
            [str(_nsz_bin()), '-D', str(nsz_path), '-o', str(work_dir)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            raise RuntimeError(f"nsz exited with code {result.returncode}")
    finally:
        if created:
            (Path.home() / '.switch' / 'prod.keys').unlink(missing_ok=True)

    # nsz names output by stem
    nsp = work_dir / (nsz_path.stem + '.nsp')
    if not nsp.exists():
        candidates = list(work_dir.glob('*.nsp'))
        if not candidates:
            raise RuntimeError("nsz produced no .nsp file")
        nsp = candidates[0]
    return nsp


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description='Convert NSP/NSZ to XCI (Mac)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s game.nsp
  %(prog)s game.nsz --keys ~/prod.keys
  %(prog)s *.nsp --output ~/xci/
""")
    p.add_argument('inputs', nargs='+', metavar='FILE', help='.nsp or .nsz file(s)')
    # Keys search order: project dir → ~/.switch/prod.keys
    _proj_keys = Path(__file__).parent / 'prod.keys'
    _default_keys = str(_proj_keys if _proj_keys.exists() else Path.home() / '.switch' / 'prod.keys')
    p.add_argument('--keys', '-k', metavar='KEYS',
                   default=_default_keys,
                   help='prod.keys path (default: project dir or ~/.switch/prod.keys)')
    p.add_argument('--output', '-o', metavar='DIR',
                   help='output directory (default: same as input)')
    p.add_argument('--nsp', action='store_true',
                   help='output NSP instead of XCI (only useful for NSZ input)')
    p.add_argument('--verbose', '-v', action='store_true')
    args = p.parse_args()

    errors = 0
    with tempfile.TemporaryDirectory(prefix='nsp2xci_') as tmp:
        for inp in args.inputs:
            inp_path = Path(inp).resolve()
            if not inp_path.exists():
                print(f"[skip] not found: {inp_path}", file=sys.stderr)
                errors += 1
                continue

            suffix = inp_path.suffix.lower()
            if suffix not in ('.nsp', '.nsz'):
                print(f"[skip] unsupported extension: {inp_path.name}", file=sys.stderr)
                errors += 1
                continue

            out_dir = Path(args.output).resolve() if args.output else inp_path.parent
            out_dir.mkdir(parents=True, exist_ok=True)

            try:
                if suffix == '.nsz':
                    keys = Path(args.keys)
                    if not keys.exists():
                        print(f"[error] prod.keys not found: {keys}", file=sys.stderr)
                        print("        use --keys to specify the path", file=sys.stderr)
                        errors += 1
                        continue
                    print(f"Decompressing {inp_path.name} …")
                    nsp_path = decompress_nsz(inp_path, tmp, keys)
                    print(f"  → {nsp_path.name}")
                else:
                    nsp_path = inp_path

                if args.nsp:
                    out_path = out_dir / (inp_path.stem + '.nsp')
                    print(f"Copying {nsp_path.name} → {out_path.name} …")
                    shutil.copy2(nsp_path, out_path)
                    print(f"  → {out_path.name}  ({os.path.getsize(out_path):,} bytes)")
                else:
                    out_path = out_dir / (inp_path.stem + '.xci')
                    print(f"Converting {nsp_path.name} → {out_path.name} …")
                    nsp_to_xci(nsp_path, out_path, verbose=args.verbose)

            except Exception as e:
                print(f"[error] {inp_path.name}: {e}", file=sys.stderr)
                if args.verbose:
                    import traceback; traceback.print_exc()
                errors += 1

    if errors:
        sys.exit(1)
    print("Done.")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
nsp2xci — Convert NSP/NSZ to XCI on macOS
Usage: python nsp2xci.py game.nsz [--keys prod.keys] [--output dir]

XCI output matches the Android app: titlekey crypto is removed from every NCA, so prod.keys
is required for XCI as well as for NSZ.
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

from Crypto.Cipher import AES

GIB = 1024 ** 3
NCA_HEADER_SIZE = 0xC00
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


def hashed_entry(name, size, leading):
    """HFS0 entry whose hash covers the first min(0x200, size) bytes of its data."""
    region = min(MEDIA, size)
    return {'name': name, 'size': size, 'hashed': region,
            'hash': hashlib.sha256(leading[:region]).digest()}


def partition_entry(name, header, total_size):
    """HFS0 entry for a nested partition; its hash covers that partition's whole HFS0 header."""
    return {'name': name, 'size': total_size, 'hashed': len(header),
            'hash': hashlib.sha256(header).digest()}


def build_hfs0_header(files):
    """
    Build an HFS0 directory header.
    files: list of {'name': str, 'size': int, optional 'hashed': int, 'hash': bytes}
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
        entries += struct.pack('<QQ', data_cursor, f['size'])           # offset, size
        entries += struct.pack('<II', name_offsets[i], f.get('hashed', 0))  # name_off, hashed_region_size
        entries += b'\x00' * 8                                          # reserved
        entries += f.get('hash', b'\x00' * 32)                          # SHA-256 of hashed region
        data_cursor += f['size']

    header = b'HFS0'
    # Readers find data at 0x10 + entries + strtab_size, so padding counts as strtab.
    padded_strtab = header_size - 0x10 - len(files) * 0x40
    header += struct.pack('<III', len(files), padded_strtab, 0)
    header += entries
    header += string_table
    header += b'\x00' * (header_size - len(header))
    return header, header_size


# ─── Keys, tickets and NCA headers ────────────────────────────────────────────

def load_keys(path):
    keys = {}
    for line in Path(path).read_text(errors='ignore').splitlines():
        line = line.strip()
        if not line or line[0] in '#;' or '=' not in line:
            continue
        name, value = line.split('=', 1)
        try:
            keys[name.strip().lower()] = bytes.fromhex(value.strip())
        except ValueError:
            continue
    return keys


def _aes_ecb(key, data, encrypt):
    c = AES.new(key, AES.MODE_ECB)
    return c.encrypt(data) if encrypt else c.decrypt(data)


def _need(keys, name, generation=None):
    full = name if generation is None else f'{name}_{generation:02x}'
    value = keys.get(full)
    if value is None or len(value) != 16:
        raise ValueError(
            f'prod.keys is too old for this game (missing key generation {generation:02x}). Dump newer keys.'
            if generation is not None else f'prod.keys is missing {name}')
    return value


def _master_key(keys, generation):
    return _need(keys, 'master_key', generation)


def titlekek(keys, generation):
    direct = keys.get(f'titlekek_{generation:02x}')
    if direct and len(direct) == 16:
        return direct
    return _aes_ecb(_master_key(keys, generation), _need(keys, 'titlekek_source'), False)


def key_area_key_application(keys, generation):
    direct = keys.get(f'key_area_key_application_{generation:02x}')
    if direct and len(direct) == 16:
        return direct
    kek = _aes_ecb(_master_key(keys, generation), _need(keys, 'aes_kek_generation_source'), False)
    source_kek = _aes_ecb(kek, _need(keys, 'key_area_key_application_source'), False)
    return _aes_ecb(source_kek, _need(keys, 'aes_key_generation_source'), False)


def parse_ticket(data):
    """Returns (rights_id, encrypted_titlekey, personalized)."""
    sig_type = struct.unpack('<I', data[:4])[0]
    block = {0x10000: 0x200 + 0x3C, 0x10003: 0x200 + 0x3C,
             0x10001: 0x100 + 0x3C, 0x10004: 0x100 + 0x3C,
             0x10002: 0x3C + 0x40, 0x10005: 0x3C + 0x40}.get(sig_type)
    if block is None:
        raise ValueError(f'Unsupported ticket signature type {sig_type:#x}')
    d = 4 + block
    if len(data) < d + 0x180:
        raise ValueError('Ticket is truncated')
    return data[d + 0x160:d + 0x170], data[d + 0x40:d + 0x50], data[d + 0x141] != 0


class NcaHeaderCipher:
    """AES-XTS for NCA headers: 0x200-byte sectors, tweak is the big-endian sector number."""

    def __init__(self, header_key):
        self.data = header_key[:16]
        self.tweak = header_key[16:32]

    def _xts(self, buf, offset, length, first_sector, encrypt):
        data_cipher = AES.new(self.data, AES.MODE_ECB)
        tweak_cipher = AES.new(self.tweak, AES.MODE_ECB)
        for s in range(length // MEDIA):
            tweak = bytearray(tweak_cipher.encrypt((first_sector + s).to_bytes(16, 'big')))
            base = offset + s * MEDIA
            for b in range(0, MEDIA, 16):
                block = bytes(x ^ y for x, y in zip(buf[base + b:base + b + 16], tweak))
                block = data_cipher.encrypt(block) if encrypt else data_cipher.decrypt(block)
                buf[base + b:base + b + 16] = bytes(x ^ y for x, y in zip(block, tweak))
                carry = 0
                for i in range(16):
                    v = (tweak[i] << 1) | carry
                    carry = v >> 8
                    tweak[i] = v & 0xFF
                if carry:
                    tweak[0] ^= 0x87

    def decrypt(self, encrypted):
        out = bytearray(encrypted[:NCA_HEADER_SIZE])
        self._xts(out, 0, MEDIA * 2, 0, False)
        magic = bytes(out[0x200:0x204])
        if magic == b'NCA3':
            self._xts(out, 0x400, MEDIA * 4, 2, False)
        elif magic == b'NCA2':
            for i in range(4):
                self._xts(out, 0x400 + i * MEDIA, MEDIA, 0, False)
        else:
            raise ValueError('Could not decrypt NCA header (wrong header_key in prod.keys?)')
        return bytes(out)

    def encrypt(self, decrypted):
        out = bytearray(decrypted[:NCA_HEADER_SIZE])
        magic = bytes(out[0x200:0x204])
        if magic == b'NCA3':
            self._xts(out, 0x400, MEDIA * 4, 2, True)
        else:
            for i in range(4):
                self._xts(out, 0x400 + i * MEDIA, MEDIA, 0, True)
        self._xts(out, 0, MEDIA * 2, 0, True)
        return bytes(out)


def key_generation(header):
    g = max(header[0x206], header[0x220])
    return g - 1 if g > 0 else 0


def remove_title_rights(header, title_key, keys):
    """Move the titlekey into the NCA key area and clear the rights ID, so no ticket is needed.
    Section data stays untouched because it is still encrypted with the same key."""
    out = bytearray(header)
    kak = key_area_key_application(keys, key_generation(header))
    for slot in range(4):
        plain = title_key if slot == 2 else b'\x00' * 16
        out[0x300 + slot * 16:0x310 + slot * 16] = _aes_ecb(kak, plain, True)
    out[0x207] = 0                      # key area encryption key index: application
    out[0x230:0x240] = b'\x00' * 16     # rights ID
    return bytes(out)


def gamecard_size_byte(total):
    for limit, code in ((1, 0xFA), (2, 0xF8), (4, 0xF0), (8, 0xE0), (16, 0xE1)):
        if total <= limit * GIB:
            return code
    return 0xE2


# ─── XCI writer ───────────────────────────────────────────────────────────────

def plan_secure_partition(f, files, keys):
    """
    Game cards carry only NCAs, and their NCAs never use titlekey crypto. For every eShop NCA the
    titlekey from the matching ticket is moved into the NCA key area, so the resulting card image
    loads without tickets, like cards produced by other XCI tools.

    Returns a list of {'file', 'entry', 'header'} where header is the replacement for the first
    0xC00 bytes of the NCA (or None to copy it unchanged).
    """
    tickets = {}
    for t in files:
        if t['name'].lower().endswith('.tik'):
            f.seek(t['offset'])
            rights_id, enc_key, personalized = parse_ticket(f.read(t['size']))
            tickets[rights_id] = (enc_key, personalized)

    header_key = keys.get('header_key')
    if not header_key or len(header_key) != 32:
        raise ValueError('prod.keys is missing header_key')
    cipher = NcaHeaderCipher(header_key)

    planned = []
    for nca in files:
        if not nca['name'].lower().endswith('.nca'):
            continue
        if nca['size'] < NCA_HEADER_SIZE:
            raise ValueError(f"{nca['name']} is not a valid NCA")
        f.seek(nca['offset'])
        original = f.read(NCA_HEADER_SIZE)
        header = cipher.decrypt(original)
        replacement = None
        if any(header[0x230:0x240]):
            ticket = tickets.get(header[0x230:0x240])
            if ticket is None:
                raise ValueError(f"{nca['name']} needs a ticket (.tik) that this file doesn't include")
            enc_key, personalized = ticket
            if personalized:
                raise ValueError("This game has a personalized ticket, which can't be converted to XCI")
            title_key = _aes_ecb(titlekek(keys, key_generation(header)), enc_key, False)
            replacement = cipher.encrypt(remove_title_rights(header, title_key, keys))
        planned.append({
            'file': nca,
            'entry': hashed_entry(nca['name'], nca['size'], replacement or original),
            'header': replacement,
        })
    return planned


def nsp_to_xci(nsp_path, out_path, keys, verbose=False):
    nsp_path = Path(nsp_path)
    out_path = Path(out_path)

    files = parse_pfs0(nsp_path)
    if verbose:
        print(f"  {len(files)} files in NSP:")
        for f in files:
            print(f"    {f['name']}  {f['size']:,} B")

    with open(nsp_path, 'rb') as nsp:
        secure_files = plan_secure_partition(nsp, files, keys)

    # ── Build "secure" partition HFS0 (NCAs only) ───────────────────────────
    secure_hdr, _ = build_hfs0_header([p['entry'] for p in secure_files])
    secure_total = len(secure_hdr) + sum(p['entry']['size'] for p in secure_files)

    # ── Build root HFS0: update, normal (empty), secure ─────────────────────
    # Emulators (yuzu/Eden) require a "normal" partition, so add empty update/normal
    # partitions ahead of secure, matching real cartridge dumps.
    empty_hdr, _ = build_hfs0_header([])
    root_hdr, root_data_start = build_hfs0_header([
        partition_entry('update', empty_hdr, len(empty_hdr)),
        partition_entry('normal', empty_hdr, len(empty_hdr)),
        partition_entry('secure', secure_hdr, secure_total),
    ])

    # Physical layout inside XCI:
    #   XCI_HFS0_OFFSET                          : root HFS0 header
    #   XCI_HFS0_OFFSET + root_data_start        : empty "update", then empty "normal"
    #   ↑ + 2 * len(empty_hdr)                   : "secure" partition (HFS0 header + NCAs)
    secure_phys_offset = XCI_HFS0_OFFSET + root_data_start + 2 * len(empty_hdr)
    secure_offset_media = secure_phys_offset // MEDIA

    total_size = secure_phys_offset + secure_total
    valid_end = _align(total_size, MEDIA) // MEDIA

    hdr  = b'\x00' * 0x100                              # RSA-2048 signature (zeroed)
    hdr += b'HEAD'                                       # magic
    hdr += struct.pack('<I', secure_offset_media)        # secureOffset
    hdr += struct.pack('<I', 0xFFFFFFFF)                 # backupOffset
    hdr += struct.pack('<BBBB', 0, gamecard_size_byte(total_size), 0, 0)  # kek index, size, version, flags
    hdr += struct.pack('<Q', 0)                          # packageId
    hdr += struct.pack('<Q', valid_end)                  # validDataEndOffset
    hdr += b'\x00' * 0x10                               # gamecardInfo (encrypted, zeroed)
    hdr += struct.pack('<Q', XCI_HFS0_OFFSET)            # hfs0Offset  (bytes, not media units)
    hdr += struct.pack('<Q', len(root_hdr))              # hfs0HeaderSize
    hdr += hashlib.sha256(root_hdr).digest()             # hfs0HeaderHash
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
        out.write(b'\x00' * (XCI_HFS0_OFFSET - 0x200))  # 0x200 – 0xEFFF reserved / gamecard cert
        out.write(root_hdr)                              # 0xF000 root HFS0 header
        out.write(empty_hdr)                             # empty "update" partition
        out.write(empty_hdr)                             # empty "normal" partition
        out.write(secure_hdr)                            # secure partition HFS0 header

        with open(nsp_path, 'rb') as nsp:
            for p in secure_files:
                nca = p['file']
                if verbose:
                    note = 'titlekey removed' if p['header'] else 'unchanged'
                    print(f"  writing {nca['name']} ({note}) …")
                skip = 0
                if p['header'] is not None:
                    out.write(p['header'])
                    skip = NCA_HEADER_SIZE
                nsp.seek(nca['offset'] + skip)
                remaining = nca['size'] - skip
                while remaining:
                    chunk = nsp.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ValueError(f"Unexpected end of file while copying {nca['name']}")
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
  %(prog)s game.nsz --nsp
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
                   help='output NSP instead of XCI (NSZ input only)')
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
                # NSZ needs keys to decompress, and XCI output needs them to move titlekeys
                # into the NCAs. A plain NSP converted to NSP would just be a copy.
                if suffix == '.nsp' and args.nsp:
                    print(f"[skip] {inp_path.name} is already an NSP; use --nsp only with NSZ input")
                    continue
                keys_path = Path(args.keys)
                if not keys_path.exists():
                    print(f"[error] prod.keys not found: {keys_path}", file=sys.stderr)
                    print("        use --keys to specify the path", file=sys.stderr)
                    errors += 1
                    continue

                if suffix == '.nsz':
                    print(f"Decompressing {inp_path.name} …")
                    nsp_path = decompress_nsz(inp_path, tmp, keys_path)
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
                    nsp_to_xci(nsp_path, out_path, load_keys(keys_path), verbose=args.verbose)

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

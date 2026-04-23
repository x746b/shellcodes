#!/usr/bin/env python3
"""
xor_url.py – generate a C‑style byte array for the URL obfuscation
used in shldr.cpp.

Usage:
    python3 url_obfuscator.py <url> <key> [--c-init]

    <url>   : the URL you want to embed, e.g. http://10.10.10.10/data.enc
    <key>   : XOR key in hex (0xNN) or decimal (e.g. 85)
    --c-init: include the surrounding “{ … }” so you can paste straight into
              the source file.
"""
import sys

def parse_key(s: str) -> int:
    """Accept hex (0xNN) or decimal."""
    return int(s, 0)   # int(..., 0) auto‑detects base

def xor_bytes(url: str, key: int) -> list[int]:
    """Return list of XOR‑ed byte values."""
    return [ord(ch) ^ key for ch in url]

def format_c_init(bytes_list: list[int]) -> str:
    """C‑style initializer, 8 bytes per line for readability."""
    lines = []
    for i in range(0, len(bytes_list), 8):
        chunk = bytes_list[i:i+8]
        line = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append('    ' + line + (',' if i + 8 < len(bytes_list) else ''))
    return '{\n' + '\n'.join(lines) + '\n}'

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 url_obfuscator.py <url> <key> [--c-init]")
        sys.exit(1)

    url = sys.argv[1]
    key = parse_key(sys.argv[2])
    # Normalize arguments to handle Unicode dash variants
    norm_args = [arg.replace('\u2010', '-').replace('\u2011', '-').replace('\u2012', '-').replace('\u2013', '-').replace('\u2014', '-') for arg in sys.argv]
    want_c_init = '--c-init' in norm_args

    xb = xor_bytes(url, key)

    if want_c_init:
        print(format_c_init(xb))
    else:
        print(', '.join(f'0x{b:02x}' for b in xb))
        # sanity check: decode back and compare
        decoded = ''.join(chr(b ^ key) for b in xb)
        print('Decoded matches original?', decoded == url)

if __name__ == '__main__':
    main()

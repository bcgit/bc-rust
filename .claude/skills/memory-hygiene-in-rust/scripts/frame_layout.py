#!/usr/bin/env python3
"""Summarise rustc/LLVM stack-frame remarks: per-function frame sizes and large stack objects.

Build with (stable toolchain is fine):
    RUSTFLAGS="-C remark=stack-frame-layout -C remark=prologepilog -C debuginfo=1" \
      CARGO_TARGET_DIR=/tmp/remarks cargo build --release -p <crate> --bin <bin> 2> remarks.txt
then:
    frame_layout.py remarks.txt [name-regex] [--min-object BYTES] [--top N]

Prints the largest frames ('N stack bytes in function' from the prologepilog remark) and, for each
matching function, its stack objects at or above --min-object (from the stack-frame-layout remark).
Names are demangled crudely from the v0 scheme. Start with NO name filter: the copy you are looking
for is often in a std/core frame such as core::array::drain::drain_array_with.
"""
import re, sys

def demangle(sym):
    parts = []
    for m in re.finditer(r"(\d+)(_?)([A-Za-z_][A-Za-z0-9_]*)", sym):
        n = int(m.group(1)); ident = m.group(3)[:n]
        if len(ident) == n and not ident.startswith("Cs"):
            parts.append(ident)
    return "::".join(parts) if parts else sym

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(1)
    path = args.pop(0)
    min_obj = 4096; top = 20; pattern = None
    while args:
        a = args.pop(0)
        if a == "--min-object": min_obj = int(args.pop(0))
        elif a == "--top": top = int(args.pop(0))
        else: pattern = re.compile(a)
    text = open(path, errors="replace").read()
    text = re.sub(r"_R[A-Za-z0-9_]+", lambda m: demangle(m.group(0)), text)
    text = re.sub(r"_ZN[0-9]+_?", "", text)
    text = re.sub(r"17h[0-9a-f]{16}E", "", text)
    for a, b in (("$LT$", "<"), ("$GT$", ">"), ("$u20$", " "), ("$C$", ","), ("$RF$", "&"), ("..", "::")):
        text = text.replace(a, b)

    frames = {}
    for m in re.finditer(r"(\d+) stack bytes in function '([^']+)'", text):
        frames[m.group(2)] = max(frames.get(m.group(2), 0), int(m.group(1)))
    objects = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"\s*Function: (.*)", line)
        if m: cur = m.group(1).strip(); objects.setdefault(cur, []); continue
        m = re.match(r"\s*Offset: \[SP[-+]\d+\], Type: (\w+), Align: \d+, Size: (\d+)", line)
        if m and cur is not None:
            objects[cur].append((int(m.group(2)), m.group(1)))

    noise = re.compile(r"backtrace|gimli|driftsort|panicking|rustc_demangle|std::sys|addr2line|miniz")
    rows = sorted(((sz, n) for n, sz in frames.items() if not noise.search(n) and (pattern is None or pattern.search(n))), reverse=True)
    print(f"largest frames (top {top}):")
    for sz, n in rows[:top]:
        print(f"{sz:9d}  {n[:140]}")
    print(f"\nstack objects >= {min_obj} bytes:")
    for sz, n in rows[:top]:
        big = sorted((o for o in objects.get(n, []) if o[0] >= min_obj), reverse=True)
        if big:
            print(f"  {n[:120]}")
            for osz, kind in big:
                print(f"      {osz:8d}  {kind}")

if __name__ == "__main__":
    main()

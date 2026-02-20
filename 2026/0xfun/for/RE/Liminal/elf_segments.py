#!/usr/bin/env python3
"""Parse ELF LOAD segments to get correct vaddr-to-file-offset mappings."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

# ELF64 header
e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize = struct.unpack_from("<H", data, 54)[0]
e_phnum = struct.unpack_from("<H", data, 56)[0]

print(f"Program header table: offset=0x{e_phoff:x}, entry_size={e_phentsize}, num={e_phnum}")

segments = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    p_flags = struct.unpack_from("<I", data, off + 4)[0]
    p_offset = struct.unpack_from("<Q", data, off + 8)[0]
    p_vaddr = struct.unpack_from("<Q", data, off + 16)[0]
    p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
    p_memsz = struct.unpack_from("<Q", data, off + 40)[0]

    type_names = {1: "LOAD", 2: "DYNAMIC", 6: "PHDR", 4: "NOTE", 0x6474e551: "GNU_STACK",
                  0x6474e552: "GNU_RELRO", 3: "INTERP", 0x6474e553: "GNU_PROPERTY"}
    tname = type_names.get(p_type, f"0x{p_type:x}")

    print(f"\n  Segment {i}: type={tname} flags=0x{p_flags:x}")
    print(f"    file_offset=0x{p_offset:x} vaddr=0x{p_vaddr:x}")
    print(f"    filesz=0x{p_filesz:x} memsz=0x{p_memsz:x}")

    if p_type == 1:  # LOAD
        segments.append((p_vaddr, p_offset, p_filesz, p_memsz))

print("\n\nLOAD segments summary:")
for i, (vaddr, foff, fsz, msz) in enumerate(segments):
    print(f"  LOAD[{i}]: vaddr=0x{vaddr:x} file_offset=0x{foff:x} filesz=0x{fsz:x} memsz=0x{msz:x}")
    print(f"    vaddr range: 0x{vaddr:x} - 0x{vaddr+msz:x}")
    print(f"    file range:  0x{foff:x} - 0x{foff+fsz:x}")
    print(f"    delta (vaddr - foff) = 0x{vaddr - foff:x}")

# Build a vaddr-to-foff function
def vaddr_to_foff(vaddr):
    for seg_vaddr, seg_foff, seg_fsz, seg_msz in segments:
        if seg_vaddr <= vaddr < seg_vaddr + seg_fsz:
            return seg_foff + (vaddr - seg_vaddr)
    return None

# Test some known addresses
test_addrs = [
    (0x401681, "first bit function"),
    (0x4016c7, "after speculative load"),
    (0x401440, "speculation gadget"),
    (0x401680, "ret instruction"),
    (0x40B000, "probe array (rsi)"),
    (0x40B100, "rsi+0x100"),
    (0x40B340, "rsi+0x340"),
    (0x40F280, "first table"),
    (0x42F280, "perm table"),
    (0x42F2C0, "key table"),
]

print("\n\nAddress mappings:")
for vaddr, desc in test_addrs:
    foff = vaddr_to_foff(vaddr)
    if foff is not None:
        byte_val = data[foff] if foff < len(data) else None
        print(f"  0x{vaddr:06x} ({desc:25s}) -> foff 0x{foff:05x}  byte=0x{byte_val:02x}" if byte_val is not None else f"  0x{vaddr:06x} ({desc:25s}) -> foff 0x{foff:05x}")
    else:
        print(f"  0x{vaddr:06x} ({desc:25s}) -> NOT in file")

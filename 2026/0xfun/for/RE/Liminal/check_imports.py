#!/usr/bin/env python3
"""Check PLT entries and dynamic symbols to see what the binary imports."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

# Parse dynamic symbols and strings
e_shoff = struct.unpack_from("<Q", data, 40)[0]
e_shentsize = struct.unpack_from("<H", data, 58)[0]
e_shnum = struct.unpack_from("<H", data, 60)[0]
e_shstrndx = struct.unpack_from("<H", data, 62)[0]

# Get section name string table
shstr_off = e_shoff + e_shstrndx * e_shentsize
shstr_foff = struct.unpack_from("<Q", data, shstr_off + 24)[0]
shstr_size = struct.unpack_from("<Q", data, shstr_off + 32)[0]
shstrtab = data[shstr_foff:shstr_foff + shstr_size]

def get_section_name(name_offset):
    end = shstrtab.index(0, name_offset)
    return shstrtab[name_offset:end].decode('ascii')

# Find .dynsym and .dynstr
dynsym_data = None
dynstr_data = None

for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from("<I", data, off)[0]
    sh_type = struct.unpack_from("<I", data, off + 4)[0]
    sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
    sh_size = struct.unpack_from("<Q", data, off + 32)[0]
    name = get_section_name(sh_name)

    if name == ".dynsym":
        dynsym_data = data[sh_offset:sh_offset + sh_size]
    elif name == ".dynstr":
        dynstr_data = data[sh_offset:sh_offset + sh_size]

# Parse dynamic symbols
print("=== Dynamic Symbols ===")
if dynsym_data and dynstr_data:
    entry_size = 24  # sizeof(Elf64_Sym)
    num_syms = len(dynsym_data) // entry_size
    for i in range(num_syms):
        off = i * entry_size
        st_name = struct.unpack_from("<I", dynsym_data, off)[0]
        st_info = dynsym_data[off + 4]
        st_value = struct.unpack_from("<Q", dynsym_data, off + 8)[0]
        st_size = struct.unpack_from("<Q", dynsym_data, off + 16)[0]

        name_end = dynstr_data.index(0, st_name)
        name = dynstr_data[st_name:name_end].decode('ascii')

        bind = st_info >> 4
        stype = st_info & 0xF
        bind_names = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
        type_names = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 10: "IFUNC"}

        if name:
            print(f"  [{i:2d}] {name:30s} bind={bind_names.get(bind, str(bind)):6s} type={type_names.get(stype, str(stype)):6s} value=0x{st_value:x}")

# Disassemble PLT
print("\n=== PLT Entries ===")
try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    plt_offset = 0x1020  # .plt at file offset 0x1020
    plt_size = 0x70
    code = data[plt_offset:plt_offset + plt_size]

    for insn in md.disasm(code, 0x401020):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")
except ImportError:
    pass

# Check .rodata for format strings
print("\n=== Strings in .rodata ===")
rodata_offset = 0x7000
rodata_size = 0x14b
rodata = data[rodata_offset:rodata_offset + rodata_size]

# Find null-terminated strings
i = 0
while i < len(rodata):
    end = rodata.find(0, i)
    if end == -1:
        break
    if end > i:
        s = rodata[i:end]
        try:
            decoded = s.decode('ascii')
            if len(decoded) >= 2:  # skip very short strings
                print(f"  [0x{0x407000 + i:06x}] \"{decoded}\"")
        except:
            pass
    i = end + 1

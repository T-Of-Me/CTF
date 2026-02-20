#!/usr/bin/env python3
"""
Check for init_array, constructors, or other initialization code that
might modify data at runtime.
Also check for relocations that might patch the tables.
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

# Parse ELF sections
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

print("=== ELF Sections ===")
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from("<I", data, off)[0]
    sh_type = struct.unpack_from("<I", data, off + 4)[0]
    sh_addr = struct.unpack_from("<Q", data, off + 16)[0]
    sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
    sh_size = struct.unpack_from("<Q", data, off + 32)[0]

    name = get_section_name(sh_name) if sh_name < len(shstrtab) else "?"
    type_names = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
                  5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
                  11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 0x6ffffff6: "GNU_HASH"}
    tname = type_names.get(sh_type, f"0x{sh_type:x}")

    if sh_size > 0:
        print(f"  [{i:2d}] {name:20s} type={tname:12s} addr=0x{sh_addr:x} off=0x{sh_offset:x} size=0x{sh_size:x}")

        # Check for init_array
        if name in ('.init_array', '.fini_array', '.preinit_array', '.ctors', '.dtors'):
            print(f"       *** Found {name}! Dumping contents:")
            for j in range(0, sh_size, 8):
                val = struct.unpack_from("<Q", data, sh_offset + j)[0]
                print(f"       [+0x{j:x}] = 0x{val:016x}")

# Check for RELA relocations targeting the table/probe area
print("\n=== Checking for relocations targeting table/probe area ===")
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from("<I", data, off + 4)[0]
    sh_name = struct.unpack_from("<I", data, off)[0]
    sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
    sh_size = struct.unpack_from("<Q", data, off + 32)[0]
    sh_entsize = struct.unpack_from("<Q", data, off + 56)[0]

    if sh_type == 4:  # RELA
        name = get_section_name(sh_name)
        print(f"\n  Section: {name} ({sh_size // sh_entsize} entries)")
        for j in range(0, sh_size, sh_entsize):
            r_offset = struct.unpack_from("<Q", data, sh_offset + j)[0]
            r_info = struct.unpack_from("<Q", data, sh_offset + j + 8)[0]
            r_addend = struct.unpack_from("<q", data, sh_offset + j + 16)[0]
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32

            # Check if relocation targets the table area (0x40F280-0x42F300)
            # or probe area (0x40B000-0x41E000)
            if 0x40B000 <= r_offset <= 0x42F300:
                type_names = {1: "R_X86_64_64", 2: "R_X86_64_PC32", 5: "R_X86_64_COPY",
                              6: "R_X86_64_GLOB_DAT", 7: "R_X86_64_JUMP_SLOT",
                              8: "R_X86_64_RELATIVE", 0x25: "R_X86_64_IRELATIVE"}
                tname = type_names.get(r_type, f"0x{r_type:x}")
                print(f"    offset=0x{r_offset:x} type={tname} sym={r_sym} addend={r_addend}")

# Check the DYNAMIC section for DT_INIT, DT_INIT_ARRAY
print("\n=== DYNAMIC section entries ===")
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from("<I", data, off + 4)[0]
    if sh_type == 6:  # DYNAMIC
        sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
        sh_size = struct.unpack_from("<Q", data, off + 32)[0]
        for j in range(0, sh_size, 16):
            d_tag = struct.unpack_from("<Q", data, sh_offset + j)[0]
            d_val = struct.unpack_from("<Q", data, sh_offset + j + 8)[0]
            tag_names = {0: "NULL", 1: "NEEDED", 5: "STRTAB", 6: "SYMTAB",
                         12: "INIT", 13: "FINI", 25: "INIT_ARRAY", 26: "FINI_ARRAY",
                         27: "INIT_ARRAYSZ", 28: "FINI_ARRAYSZ"}
            tname = tag_names.get(d_tag, f"0x{d_tag:x}")
            if d_tag in (12, 13, 25, 26, 27, 28):
                print(f"  {tname:20s} = 0x{d_val:x}")
            if d_tag == 0:
                break

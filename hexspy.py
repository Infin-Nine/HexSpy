#!/usr/bin/env python3

"""
HexSpy: A CLI tool for decoding and analyzing hexadecimal values
Author: Infinnine
Version: 1.1
"""

import sys
import os
from pwn import *
from capstone import *

context.log_level = 'error'  # Silence pwntools banner

KNOWN_SHELLCODES = [
    b"\x48\x31\xc0\x50\x48\x89\xe2\x50\x48\x89\xe6\xb0\x3b\x0f\x05",  # execve("/bin/sh")
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
]

def format_bytes(hex_str):
    return ' '.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])

def to_little_endian(hex_str):
    return ' '.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

def segment_guess(addr):
    if addr >= 0x7fffffff0000:
        return "Stack (Likely)"
    elif 0x600000 <= addr < 0x700000:
        return ".data / .bss section"
    elif 0x400000 <= addr < 0x500000:
        return ".text (Code) section"
    elif 0x7f0000000000 <= addr <= 0x7fffffffffff:
        return "Shared Libraries / Mapped (libc, etc)"
    else:
        return "Heap / Unknown / Not in typical memory range"

def is_probable_memory_address(value):
    return (
        (0x400000 <= value <= 0x4fffff) or        # .text
        (0x600000 <= value <= 0x6fffff) or        # .data/.bss
        (0x7ffff00000 <= value <= 0x7fffffffffff) # Stack, libc, etc
    )

def detect_shellcode(hex_bytes):
    for known in KNOWN_SHELLCODES:
        if known in hex_bytes:
            return True
    return False

def disassemble_bytes(code_bytes, addr=0x0):
    print("\n🧠 Disassembly (x86_64):")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for insn in md.disasm(code_bytes, addr):
        print("   0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

def analyze_hex(hex_input):
    print("\n================ HEXSPY ANALYSIS ================")
    hex_input = hex_input.lower().replace("0x", "").replace(" ", "")
    if len(hex_input) % 2 != 0:
        hex_input = "0" + hex_input

    try:
        value = int(hex_input, 16)
    except ValueError:
        print("\n❌ Invalid hexadecimal input.")
        return

    print(f"\n🔹 Hex Value: 0x{hex_input}")
    print(f"🔹 Decimal Value: {value}")
    print(f"🔹 Byte Count: {len(hex_input)//2} bytes")

    print(f"\n📦 Bytes (Big Endian)   : {format_bytes(hex_input)}")
    print(f"📦 Bytes (Little Endian): {to_little_endian(hex_input)}")

    # ASCII
    try:
        ascii_val = bytes.fromhex(hex_input).decode('utf-8')
    except:
        ascii_val = ''.join([chr(int(hex_input[i:i+2], 16)) if 32 <= int(hex_input[i:i+2], 16) <= 126 else '.' for i in range(0, len(hex_input), 2)])
    print(f"\n🔤 ASCII String (Printable): '{ascii_val}'")

    # Address Analysis
    if len(hex_input) in [8, 12, 16]:
        print(f"\n🧠 Address Interpretation:")
        print(f"   ➤ Possible Memory Address: 0x{hex_input}")
        print(f"   ➤ Segment Guess          : {segment_guess(value)}")
        if is_probable_memory_address(value):
            print(f"   ✅ Confirmed: Likely valid memory address")
        else:
            print(f"   ⚠️ Not a typical memory address (outside common regions)")

    # Shellcode Detection
    try:
        hex_bytes = bytes.fromhex(hex_input)
        if detect_shellcode(hex_bytes):
            print("\n💣 Shellcode Detected: Possible /bin/sh shellcode pattern")
            disassemble_bytes(hex_bytes)
    except:
        pass

    print("\n=================================================\n")

def analyze_file(filepath):
    print(f"\n📁 Analyzing hex dump of file: {filepath}\n")
    if not os.path.isfile(filepath):
        print("❌ File does not exist.")
        return
    with open(filepath, 'rb') as f:
        data = f.read()
        hex_data = data.hex()
        analyze_hex(hex_data[:64])  # Show first 32 bytes (64 hex chars)

def analyze_elf_symbols(filepath):
    print(f"\n🧠 ELF Binary Analysis: {filepath}")
    try:
        elf = ELF(filepath)
        print("\n🔧 Symbol Table:")
        for sym in elf.symbols:
            print(f"   {sym:20} => 0x{elf.symbols[sym]:x}")

        text_section = elf.get_section_by_name('.text')
        if text_section:
            print("\n📜 Disassembling .text section:")
            code = text_section.data()
            disassemble_bytes(code, text_section.header.sh_addr)

    except Exception as e:
        print(f"❌ Failed to parse ELF: {e}")

def analyze_memory_address(pid, address, length=32):
    print(f"\n🔍 Reading memory from PID {pid} at 0x{address:x}...")
    try:
        gdbscript = f"define hook-stop\n  x/{length}bx 0x{address:x}\nend\ncontinue\n"
        with open("temp.gdb", "w") as f:
            f.write(gdbscript)
        os.system(f"gdb -p {pid} -x temp.gdb")
        os.remove("temp.gdb")
    except Exception as e:
        print(f"❌ Failed to read memory: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 hexspy.py <hex_value>")
        print("  python3 hexspy.py --file <file_path>")
        print("  python3 hexspy.py --elf <elf_path>")
        print("  python3 hexspy.py --gdb <pid> <hex_address>")
        return

    if sys.argv[1] == "--file" and len(sys.argv) == 3:
        analyze_file(sys.argv[2])
    elif sys.argv[1] == "--elf" and len(sys.argv) == 3:
        analyze_elf_symbols(sys.argv[2])
    elif sys.argv[1] == "--gdb" and len(sys.argv) == 4:
        pid = int(sys.argv[2])
        addr = int(sys.argv[3], 16)
        analyze_memory_address(pid, addr)
    else:
        analyze_hex(sys.argv[1])

if __name__ == "__main__":
    main()

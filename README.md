# 🔍 HexSpy

**HexSpy** is a powerful CLI tool built for reverse engineers, binary exploit developers, and cybersecurity learners. It lets you **decode hexadecimal values**, detect and disassemble **shellcode**, analyze **ELF binaries**, and inspect **live memory** using GDB.

---

## 🚀 Features

- 🔢 **Hexadecimal Analysis** – Convert to decimal, ASCII, endian formats
- 💣 **Shellcode Detection** – Recognizes `/bin/sh` style payloads
- 🧠 **Memory Address Classification** – .text, .data, stack, heap, libc
- 📜 **Disassembly Engine** – Built-in Capstone disassembler
- 🧾 **ELF Symbol Resolver** – Reads symbols and `.text` from binaries
- 🐚 **GDB Integration** – Inspect memory from running processes
- 📂 **Hex Dump File Reader** – Analyze any raw binary file

---

## 📦 Installation

### 🔧 From Source (Recommended)

```bash
https://github.com/Infin-Nine/HexSpy.git
cd HexSpy
python3 hexspy.py
```
##### ⚙️ Dependencies
pwntools,
capstone,
Python 3.6+

#### 🧪 Usage
```
hexspy 0x7ffff7dd18e0,
hexspy --file shellcode.bin,
hexspy --elf ./ret2win,
hexspy --gdb <PID> <HEX_ADDRESS>

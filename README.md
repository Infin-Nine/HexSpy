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
git clone https://github.com/yourusername/HexSpy.git
cd HexSpy
python3 hexspy.py

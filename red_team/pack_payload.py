#!/usr/bin/env python3
import sys

XOR_KEY = 0x5A


def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <input_elf> <output_header>")

    in_path, out_path = sys.argv[1], sys.argv[2]
    with open(in_path, "rb") as f:
        raw = f.read()

    obfuscated = bytes(b ^ XOR_KEY for b in raw)

    with open(out_path, "w", encoding="utf-8") as out:
        out.write("#ifndef PAYLOAD_BYTES_H\n")
        out.write("#define PAYLOAD_BYTES_H\n\n")
        out.write("#include <stddef.h>\n")
        out.write("#include <stdint.h>\n\n")
        out.write(f"#define PAYLOAD_XOR_KEY 0x{XOR_KEY:02X}\n\n")
        out.write("static const uint8_t PAYLOAD_ENC[] = {\n")
        for i in range(0, len(obfuscated), 16):
            chunk = ", ".join(f"0x{b:02x}" for b in obfuscated[i:i + 16])
            out.write(f"    {chunk},\n")
        out.write("};\n\n")
        out.write("static const size_t PAYLOAD_LEN = sizeof(PAYLOAD_ENC);\n\n")
        out.write("#endif\n")


if __name__ == "__main__":
    main()

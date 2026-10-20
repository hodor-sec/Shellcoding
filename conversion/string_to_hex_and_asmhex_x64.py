#!/usr/bin/env python3

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate x64 assembly to push a string onto the stack."
    )
    parser.add_argument("string", help="String to convert")
    parser.add_argument(
        "--negate",
        action="store_true",
        help="Emit negated immediates and a NEG instruction before each push",
    )
    args = parser.parse_args()

    data = args.string.encode("utf-8")
    if b"\x00" in data:
        parser.error("The input string cannot contain a null byte.")

    print(f"; String length: {len(data)} bytes")
    print("xor rax, rax")
    if args.negate:
        print("neg rax")
    print("push rax                            ; Null terminator + padding")

    # Split from the end: use 4 bytes for a remainder, then 8-byte chunks.
    chunks = []
    end = len(data)
    while end > 0:
        size = 4 if end % 8 == 4 else 8
        start = max(0, end - size)
        chunks.append(data[start:end])
        end = start

    for chunk in chunks:
        comment = repr(chunk.decode("utf-8", errors="replace"))

        if len(chunk) == 4:
            value = int.from_bytes(chunk, byteorder="little")
            if args.negate:
                value = (-value) & 0xFFFFFFFF
            print(f"mov eax, 0x{value:08x}                 ; {comment}")
            if args.negate:
                print("neg eax")
            print(f"push rax                            ; {comment}")
        else:
            value = int.from_bytes(chunk, byteorder="little")
            if args.negate:
                value = (-value) & 0xFFFFFFFFFFFFFFFF
            print(f"mov rax, 0x{value:016x}         ; {comment}")
            if args.negate:
                print("neg rax")
            print(f"push rax                            ; {comment}")


if __name__ == "__main__":
    main()


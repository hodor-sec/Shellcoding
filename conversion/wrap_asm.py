import argparse
import re

def wrap_asm_file(input_file, output_file=None):
    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    wrapped_lines = []
    max_comment_length = 0

    for line in lines:
        stripped_line = line.rstrip()
        if stripped_line:
            line_parts = re.split(r'(?<=;)', stripped_line)
            code_part = line_parts[0].rstrip()
            if len(line_parts) > 1:
                comment_part = line_parts[1].strip()
            else:
                comment_part = ""
            max_comment_length = max(max_comment_length, len(code_part))
    for line in lines:
        stripped_line = line.rstrip()
        if stripped_line:
            line_parts = re.split(r'(?<=;)', stripped_line)
            code_part = line_parts[0].rstrip()
            if len(line_parts) > 1:
                comment_part = line_parts[1].strip()
            else:
                comment_part = ""

            if code_part.endswith(';'):
                formatted_code = f'"{code_part}"'
            else:
                formatted_code = f'"{code_part} ;"'

            spaces_to_add = ' ' * (max_comment_length - len(code_part))
            if comment_part:
                formatted_code += f"{spaces_to_add} # {comment_part}"

            wrapped_lines.append(formatted_code)
    if output_file:
        with open(output_file, 'w') as outfile:
            outfile.write("CODE = (\n")
            for line in wrapped_lines:
                outfile.write(f"{line}\n")
            outfile.write(")\n")
        print(f"Wrapped ASM code has been written to {output_file}")
    else:
        print("CODE = (")
        for line in wrapped_lines:
            print(line)
        print(")")

def main():
    parser = argparse.ArgumentParser(description="Wrap ASM code in a Python variable")
    parser.add_argument('input_file', help="Path to the input ASM file")
    parser.add_argument('output_file', nargs='?', help="Path to the output Python file (optional)", default=None)

    args = parser.parse_args()

    wrap_asm_file(args.input_file, args.output_file)

if __name__ == "__main__":
    main()

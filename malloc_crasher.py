import binascii
import os
import subprocess
import sys

from typing import List, Tuple

COLOR_RED = '\033[91m'
COLOR_GRN = '\033[92m'
COLOR_YLW = '\033[93m'
COLOR_END = '\033[0m'


def get_opcodes(malloc_calls: List[str]) -> List[str]:
    opcodes = []
    for call in malloc_calls:
        opcodes.append(''.join(call.split()[1:6]))
    opcodes.reverse()
    return opcodes


def get_malloc_opcodes(target_program: str) -> List[str]:
    malloc_calls = []
    disassembled = os.popen("/usr/bin/objdump -d " + target_program).read()
    for line in disassembled.split('\n'):
        for field in line.split():
            if field == "<malloc@plt>":
                malloc_calls.append(line)
    return get_opcodes(malloc_calls)


def parse_program_args(program_args: List[str]) -> Tuple[str, List[str]]:
    print(program_args)
    target_program = program_args[1]
    parameters = []
    return target_program, parameters


def infect_call(hex_content: bytes, opcode_position: int, malloc_opcode_length: int) -> bytes:
    infected_opcode: bytes = b"4831c09090"
    return hex_content[:opcode_position] + infected_opcode + hex_content[opcode_position + malloc_opcode_length:]


def infect_malloc_calls(target_program: str, malloc_opcodes: List[str]):
    crash = 0
    with open(target_program, "rb") as f:
        content = f.read()
        f.close()
    hex_content = binascii.hexlify(content)
    for opcode in malloc_opcodes:
        print(opcode)
        opcode_position = str(hex_content).find(opcode) - 2 # TODO: determine the reason for this 2 bytes offset
        print(opcode_position)
        infected_binary = infect_call(hex_content, opcode_position, len(opcode))
        infected_binary = binascii.unhexlify(infected_binary)
        new_name = target_program + ".infected"
        with open(new_name, "wb+") as f:
            f.write(infected_binary)
            f.close()
        os.chmod(new_name, 0o0777)
        print(COLOR_YLW + ">> " + new_name + " <<")
        print(COLOR_GRN + ">> ENTER TO RUN <<" + COLOR_END)
        input("")
        print(COLOR_YLW + "-> Running " + new_name + " with vulnerable code...\n")
        exit_code = subprocess.call("./" + new_name)
        print(COLOR_YLW + "CRASH : " + (COLOR_GRN + "NO" if exit_code >= 0 else COLOR_RED + "YES"))
        if exit_code < 0:
            crash += 1
        if exit_code == -11:
            print(COLOR_RED + "(SEGFAULT)")
        print(COLOR_YLW + "crash count : " + COLOR_RED + str(crash) + "/" + str(len(malloc_opcodes)) + COLOR_END)
        input("")


def main():
    target_program, parameters = parse_program_args(sys.argv)
    malloc_opcodes = get_malloc_opcodes(target_program)
    infect_malloc_calls(target_program, malloc_opcodes)


if __name__ == '__main__':
    main()

import binascii
import os
import subprocess
import sys

from typing import List, Tuple

COLOR_SIZE = 5
COLOR_RED = '\033[91m'
COLOR_GRN = '\033[92m'
COLOR_YLW = '\033[93m'
COLOR_END = '\033[00m'


class Flags():
    def __init__(self):
        self.has_interactive = False
        self.has_record = False
        self.has_output_destination = False
        self.output_destination = None


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


def get_target_program_content(target_program: str) -> str:
    with open(target_program, "rb") as f:
        content = f.read().hex()
        f.close()
    #for i in range(0, len(content), 1024):
        #print(content[i:i+1024])
    return content


def print_initial_info(infected_binary_name: str, content: str, position: int, infected_opcode: str):
    malloc = content[position : position + 10]
    l1  = " {}TARGET CODE{} ".format(COLOR_GRN, COLOR_END)
    l2  = " {}malloc call {}{}/{}{}".format(COLOR_YLW, COLOR_GRN, 1, 2, COLOR_END)
    l3  = "... " + content[position - 38: position - 9]
    l4  = (
            content[position - 9 : position] +
            "{}[{}]{}".format(COLOR_GRN, content[position : position + 10], COLOR_END) +
            content[position + 10 : position + 10 + 12]
    )
    l5 = content[position + 10 + 12 : position + 51] + " ..."
    l6 = " {}[call malloc] {}{}".format(COLOR_GRN, " ".join([malloc[i:i+2] for i in range(0, len(malloc), 2)]), COLOR_END)
    print(" " + l1.center(37 + COLOR_SIZE * 2, "-") + " ")
    print("| " + l2.center(35 + COLOR_SIZE * 3, " ") + " |")
    print("| " + l3.center(35, " ") + " |")
    print("| " + l4.center(35 + COLOR_SIZE * 2, " ") + " |")
    print("| " + l5.center(35, " ") + " |")
    print("| " + l6.ljust(35 + COLOR_SIZE * 2, " ") + " |")
    #print(COLOR_YLW + ">> " + infected_binary_name + " <<")


def prompt_user_to_proceed(infected_binary_name: str):
    print(COLOR_GRN + ">> ENTER TO RUN <<" + COLOR_END)
    input("")
    print(COLOR_YLW + "-> Running " + infected_binary_name + " with vulnerable code...\n")


def create_infected_binary(infected_binary_name: str, source_binary_content: str, opcode_position: int, opcode_length: int):
    infected_opcode: str = "4831c09090" # Xor RAX register + 2 NO-OPS to override total malloc opcode length
    infected_content = (
            source_binary_content[:opcode_position]
            + infected_opcode
            + source_binary_content[opcode_position + opcode_length:]
    )
    infected_binary_content = binascii.unhexlify(infected_content)
    with open(infected_binary_name, "wb+") as f:
        f.write(infected_binary_content)
        f.close()
    os.chmod(infected_binary_name, 0o0777)


def print_execution_info(infected_binary_exit_code: int):
    print(COLOR_YLW + "CRASH : " + (COLOR_GRN + "NO" if infected_binary_exit_code >= 0 else COLOR_RED + "YES"))
    if infected_binary_exit_code == -11:
        print(COLOR_RED + "(SEGFAULT)")


def run_infected_binary(flags: Flags, infected_binary_name: str) -> int:
    crash: int = 0
    exit_code: int = subprocess.call("./" + infected_binary_name)
    if exit_code < 0:
        crash = 1
    if flags.has_interactive:
        print_execution_info(exit_code)
    return crash


def print_crash_count(crash_count: int, total_nbr_of_executions: int):
    print(COLOR_YLW + "crash count : " + COLOR_RED + str(crash_count) + "/" + str(total_nbr_of_executions) + COLOR_END)
    input("")


def main():
    crash_count = 0
    flags = Flags()
    flags.has_interactive = True
    target_program, parameters = parse_program_args(sys.argv)
    malloc_opcodes = get_malloc_opcodes(target_program)
    source_binary_content: str = get_target_program_content(target_program)
    for opcode in malloc_opcodes:
        print(opcode)
        opcode_position = source_binary_content.find(opcode) # TODO: determine the reason for this 2 bytes offset
        print(opcode_position)
        infected_binary_name: str = target_program + ".infected"
        create_infected_binary(infected_binary_name, source_binary_content, opcode_position, len(opcode))
        if flags.has_interactive:
            print_initial_info(infected_binary_name, source_binary_content, opcode_position, "4831c09090")
            prompt_user_to_proceed(infected_binary_name)
        crash_count += run_infected_binary(flags, infected_binary_name)
        print_crash_count(crash_count, len(malloc_opcodes))


if __name__ == '__main__':
    main()

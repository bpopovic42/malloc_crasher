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


def print_initial_info(content: str, position: int, total_calls: int, call_count: int):
    malloc: str = content[position: position + 10]
    l1: str = " {}TARGET CODE{} ".format(COLOR_GRN, COLOR_END)
    l2: str = " {}malloc call {}{}/{}{}".format(COLOR_YLW, COLOR_GRN, call_count, total_calls, COLOR_END)
    l3: str = "... " + content[position - 38: position - 9]
    l4: str = (
            content[position - 9: position] +
            "{}[{}]{}".format(COLOR_GRN, content[position: position + 10], COLOR_END) +
            content[position + 10: position + 10 + 12]
    )
    l5: str = content[position + 10 + 12: position + 51] + " ..."
    l6: str = " {}[call malloc] {}{}".format(COLOR_GRN, " ".join([malloc[i:i + 2] for i in range(0, len(malloc), 2)]),
                                             COLOR_END)
    print(" " + l1.center(37 + COLOR_SIZE * 2, "-") + " ")
    print("| " + l2.center(35 + COLOR_SIZE * 3, " ") + " |")
    print("| " + l3.center(35, " ") + " |")
    print("| " + l4.center(35 + COLOR_SIZE * 2, " ") + " |")
    print("| " + l5.center(35, " ") + " |")
    print("| " + l6.ljust(35 + COLOR_SIZE * 2, " ") + " |")
    print(" " + "".center(37, "-"))


def print_infection(content: str, position: int, total_calls: int, calls_count: int):
    original_malloc: str = content[position: position + 10]
    l1: str = " {}POISONED CODE{} ".format(COLOR_RED, COLOR_END)
    l2: str = " {}malloc call {}{}/{}{}".format(COLOR_YLW, COLOR_GRN, calls_count, total_calls, COLOR_END)
    l3: str = "... " + content[position - 38: position - 9]
    l4: str = (
            content[position - 9: position] +
            "{}[4831C0][90][90]{}".format(COLOR_RED, COLOR_END) +
            content[position + 10: position + 10 + 8]
    )
    l5: str = content[position + 10 + 8: position + 47] + " ..."
    l6: str = " {}+ [xor rax, rax] 48 31 C0{}".format(COLOR_RED, COLOR_END)
    l7: str = " {}+ [nop]          90{}".format(COLOR_RED, COLOR_END)
    l8: str = " {}- [call malloc]  {}{}".format(COLOR_GRN, " ".join(
        [original_malloc[i:i + 2] for i in range(0, len(original_malloc), 2)]), COLOR_END)
    print(" " + l1.center(37 + COLOR_SIZE * 2, "-") + " ")
    print("| " + l2.center(35 + COLOR_SIZE * 3, " ") + " |")
    print("| " + l3.center(35, " ") + " |")
    print("| " + l4.center(35 + COLOR_SIZE * 2, " ") + " |")
    print("| " + l5.center(35, " ") + " |")
    print("| " + l6.ljust(35 + COLOR_SIZE * 2, " ") + " |")
    print("| " + l7.ljust(35 + COLOR_SIZE * 2, " ") + " |")
    print("| " + l7.ljust(35 + COLOR_SIZE * 2, " ") + " |")
    print("| " + l8.ljust(35 + COLOR_SIZE * 2, " ") + " |")
    print(" " + "".center(37, "-"))


def prompt_user_to_proceed(infected_binary_name: str):
    print(COLOR_GRN + ">> ENTER TO RUN <<".center(35, " ") + COLOR_END)
    input("")
    print(COLOR_YLW + ("-> Running " + infected_binary_name + " with vulnerable code...\n") + COLOR_END)


def print_execution_info(infected_binary_process: subprocess.CompletedProcess, total_nbr_of_calls: int, crash_count: int):
    infected_binary_stdout: str = infected_binary_process.stdout.decode("utf-8")
    infected_binary_stderr: str = infected_binary_process.stderr.decode("utf-8")
    if infected_binary_stdout == "" and infected_binary_stderr == "":
        print(COLOR_YLW + "Target output is empty\n" + COLOR_END)
    else:
        print(COLOR_YLW + "Target output :" + COLOR_END)
        if infected_binary_stdout != "": print(infected_binary_stdout)
        if infected_binary_stderr != "": print(infected_binary_stderr)
    print(COLOR_YLW + "CRASH : " + COLOR_END, end="")
    if infected_binary_process.returncode < 0:
        print(COLOR_RED + "YES" + (" (SEGFAULT)" + COLOR_END) if infected_binary_process.returncode == -11 else COLOR_END)
    else:
        print(COLOR_GRN + "NO" + COLOR_END)
    print(COLOR_GRN + "Crash count : {}/{}".format(crash_count, total_nbr_of_calls) + COLOR_END)
    input("")


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
    target_program = program_args[1]
    parameters = []
    return target_program, parameters


def get_target_program_content(target_program: str) -> str:
    with open(target_program, "rb") as f:
        content = f.read().hex()
        f.close()
    return content


def create_infected_binary(infected_binary_name: str, source_binary_content: str, opcode_position: int,
                           opcode_length: int):
    infected_opcode: str = "4831c09090"  # Xor RAX register + 2 NO-OPS to override total malloc opcode length
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


def run_infected_binary(flags: Flags, infected_binary_name: str) -> subprocess.CompletedProcess:
    infected_binary_process: subprocess.CompletedProcess = subprocess.run(["./" + infected_binary_name], capture_output=True)
    return infected_binary_process


def main():
    crash_count: int = 0
    calls_count: int = 1
    flags = Flags()
    flags.has_interactive = True
    target_program, parameters = parse_program_args(sys.argv)
    malloc_opcodes = get_malloc_opcodes(target_program)
    source_binary_content: str = get_target_program_content(target_program)
    for opcode in malloc_opcodes:
        os.system('clear')
        opcode_position = source_binary_content.find(opcode)
        infected_binary_name: str = target_program + ".infected"
        create_infected_binary(infected_binary_name, source_binary_content, opcode_position, len(opcode))
        if flags.has_interactive:
            print_initial_info(source_binary_content, opcode_position, len(malloc_opcodes), calls_count)
            print_infection(source_binary_content, opcode_position, len(malloc_opcodes), calls_count)
            prompt_user_to_proceed(infected_binary_name)
        infected_binary_process: subprocess.CompletedProcess = run_infected_binary(flags, infected_binary_name)
        crash_count += 1 if infected_binary_process.returncode < 0 else 0
        if flags.has_interactive:
            print_execution_info(infected_binary_process, len(malloc_opcodes), crash_count)
        calls_count += 1


if __name__ == '__main__':
    main()

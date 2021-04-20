import binascii
import os
import subprocess
import sys

from typing import List, Tuple, Optional

COLOR_SIZE = 5
COLOR_RED = '\033[91m'
COLOR_GRN = '\033[92m'
COLOR_YLW = '\033[93m'
COLOR_END = '\033[00m'


class Flags():
    def __init__(self):
        self.has_print = False
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
    os.system('clear')
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


def print_execution_info(infected_binary_process: subprocess.CompletedProcess, total_nbr_of_calls: int,
                         crash_count: int):
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
        print(
            COLOR_RED + "YES" + (" (SEGFAULT)" + COLOR_END) if infected_binary_process.returncode == -11 else COLOR_END)
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


def get_target_program_content(target_program: str) -> str:
    with open(target_program, "rb") as f:
        content = f.read().hex()
        f.close()
    return content


def create_infected_binary(infected_binary_name: str, original_binary_content: str, opcode_position: int,
                           opcode_length: int):
    infected_opcode: str = "4831c09090"  # Xor RAX register + 2 NO-OPS to override total malloc opcode length
    infected_content = (
            original_binary_content[:opcode_position]
            + infected_opcode
            + original_binary_content[opcode_position + opcode_length:]
    )
    infected_binary_content = binascii.unhexlify(infected_content)
    with open(infected_binary_name, "wb+") as f:
        f.write(infected_binary_content)
        f.close()
    os.chmod(infected_binary_name, 0o0777)


def run_infected_binary(flags: Flags, infected_binary_name: str) -> subprocess.CompletedProcess:
    infected_binary_process: subprocess.CompletedProcess = subprocess.run(["./" + infected_binary_name],
                                                                          capture_output=True)
    return infected_binary_process


def get_infected_binary_name(flags: Flags, original_binary_name: str, calls_count: int) -> str:
    infected_binary_name: str = original_binary_name + ".infected"
    if flags.has_record:
        infected_binary_name += "_" + str(calls_count).zfill(3)
    return infected_binary_name


def run_infections(flags: Flags, original_binary_name: str, original_binary_content: str,
                   malloc_opcodes: List[str]) -> int:
    crash_count: int = 0
    calls_count: int = 1
    for opcode in malloc_opcodes:
        infected_binary_name: str = get_infected_binary_name(flags, original_binary_name, calls_count)
        opcode_position = original_binary_content.find(opcode)
        create_infected_binary(infected_binary_name, original_binary_content, opcode_position, len(opcode))
        if flags.has_print:
            print_initial_info(original_binary_content, opcode_position, len(malloc_opcodes), calls_count)
            print_infection(original_binary_content, opcode_position, len(malloc_opcodes), calls_count)
            prompt_user_to_proceed(infected_binary_name)
        infected_binary_process: subprocess.CompletedProcess = run_infected_binary(flags, infected_binary_name)
        crash_count += 1 if infected_binary_process.returncode < 0 else 0
        if flags.has_print:
            print_execution_info(infected_binary_process, len(malloc_opcodes), crash_count)
        calls_count += 1
        return crash_count


def print_usage():
    print(
        "USAGE: ./malloc_crasher [OPTION]... [ELF_BINARY]\n"
        "Sequentially replaces every call to malloc in [ELF_BINARY] by a custom opcode sequence returning NULL.\n"
        "Checks whether each of those calls were properly protected against allocation failures by looking at the infected"
        " [ELF_BINARY]'s exit code\n"
        "\n"
        "OPTIONS:\n"
        "\t-h" "\t\t" "Print this message.\n"
        "\t-o [PATH]" "\t" "Use [PATH] as an output directory for infected binaries produced by this program.\n"
        "\t-p" "\t\t" "Print info and results during execution. (Print mode)\n"
        "\t-r" "\t\t" "Record every replaced call to malloc into its own separate binary.\n"
        "\n"
        "EXIT STATUS:\n"
        "\t0 if OK,\n"
        "\t1 if unprotected mallocs were found,\n"
        "\t-1 in case of error (e.g, invalid command-line argument).\n"
        "\n"
        "NOTES:\n"
        "This program requires python 3.8"
    )


def set_command_line_flags(flags: Flags, flag_list: str, next_argument: Optional[str]) -> int:
    if "h" in flag_list:
        print_usage()
        exit(0)
    for flag in flag_list:
        if flag == "p":
            flags.has_print = True
        elif flag == "o":
            if not next_argument or not os.path.isdir(next_argument):
                print("Error: Invalid output directory '{}'")
                return 1
            else:
                flags.has_output_destination = True
                flags.output_destination = next_argument
        elif flag == "r":
            flags.has_record = True
    return 0


def parse_program_args(program_args: List[str]) -> Tuple[str, Flags]:
    flags: Flags = Flags()
    target_binary: Optional[str] = None
    if len(program_args) < 2:
        print_usage()
        exit(-1)
    for i in range(0, len(program_args)):
        next_argument: Optional[str] = program_args[i + 1] if i < len(program_args) - 1 else None
        if i == 0:
            pass
        elif program_args[i][0] == "-":
            if set_command_line_flags(flags, program_args[i][1:], next_argument) == 1:
                print("Run './{} -h' for usage".format(program_args[0]))
                exit(-1)
            if "o" in program_args[i]:  # If output directory flag
                i += 1  # Skip the following argument
        else:
            if not target_binary:
                target_binary = program_args[i]
            else:
                print("Error: Multiple targets provided\n")
                print("Run './{} -h' for usage".format(program_args[0]))
                exit(-1)
        i += 1
        print(i)
    if not target_binary:
        print("Error: No target specified\n"
              "Run ./{} -h for usage".format(program_args[0]))
        exit(-1)
    return target_binary, flags


def main():
    original_binary_name: str
    flags: Flags
    original_binary_name, flags = parse_program_args(sys.argv)
    malloc_opcodes: List[str] = get_malloc_opcodes(original_binary_name)
    original_binary_content: str = get_target_program_content(original_binary_name)
    crashes: int = run_infections(flags, original_binary_name, original_binary_content, malloc_opcodes)
    exit(1 if crashes > 0 else 0)


if __name__ == '__main__':
    main()

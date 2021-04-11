import os
import sys


def get_symbols():
    malloc_calls = []
    if len(sys.argv) >= 2:
        global prog_name
        prog_name = sys.argv[1]
    os.system("/usr/bin/objdump -d " + prog_name + " | grep malloc > .sym_logs")
    with open(".sym_logs", "r") as dump_file:
        for line in dump_file:
            splitted = line.split()
            for elem in splitted:
                #print(elem)
                if elem == "<malloc@plt>":
                    #print(line)
                    malloc_calls.append(line)
        print(malloc_calls)


def main():
    get_symbols()


if __name__ == '__main__':
    main()

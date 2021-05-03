# malloc_crasher

## Introduction
This is my own take at an improved version of https://github.com/ataguiro/mc  
  
This program allows you to test the behavior of a compiled 64bit ELF binary in case of malloc failure.  
  
It works by sequentially replacing and testing the various calls to malloc from the original ELF binary with a custom opcode sequence, essentially turning the calls into NULL returns.  
  
For each of those calls it will check the exit code of the binary, any exit code lower than 0 is considered as a crash.

## Usage

## Limitations

## Notes
This program requires python version >= 3.8  
  
Only works with 64bit ELF binaries  

# malloc_crasher

## Introduction
This is my own attempt at an improved version of this project : https://github.com/ataguiro/mc  
  
This program allows you to test the behavior of a compiled 64bit ELF binary in case of malloc failure.  
  
It works by sequentially modifiying and testing the various calls to malloc from the original ELF binary replacing them with a custom opcode sequence, essentially turning the calls into NULL returns.  
  
For each of those calls it will check the exit code of the binary, any exit code lower than 0 is considered as a crash occurence.

## Usage
```
USAGE: ./malloc_crasher [OPTION]... [ELF_BINARY]

OPTIONS:
	-a "[ARGS]"	Pass [ARGS] for each infected binary to be run with.
	-h		Print this message.
	-o [PATH]	Use [PATH] as an output directory for infected binaries produced by this program.
	-p		Print info and results during execution. (Print mode)
	-r		Record every replaced call to malloc into its own separate binary.

EXIT STATUS:
	0 if OK,
	1 if unprotected mallocs were found,
	-1 in case of error (e.g, invalid command-line argument).
```

## Limitations
WIP

## Notes
This program requires python version >= 3.8  
  
Only works with 64bit ELF binaries  
  
Many thanks to [ataguiro](https://github.com/ataguiro) for the original method and project
  
### Reasons for this rework and differences with the original project
When I first stumbled across [this piece of code](https://github.com/ataguiro/mc) some years ago, I had trouble making sense of it, it kind of seemed like black magic to me at the time.  
  
Later on when I got back to working on 42's C projects, I naturally started using it again and went through its code once more.  
Thanks to the progress I've since made in both low-level programming and python, I was now able to understand its mechanism with much more ease.  
Still the code was pretty obscure in some parts which I naturally started cleaning up as I went through it.  
   
In the end I tried to make it more readable so that neophytes like the one I was could have an easier time understanding how it works, consequently I added options to facilitate its overall usage and potential integrations in other testing utilities.  
That being said some parts of the code are still pretty obscure, the display implementation in particular which I'm not satisfied with.
  

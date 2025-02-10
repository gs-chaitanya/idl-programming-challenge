# Challenge

Create a program in a language of your choice that implements a Physical Memory Protection (PMP) check according to Chapter 3.7 of the RISC-V privleged manual (https://drive.google.com/file/d/17GeetSnT5wW3xNuAHI95-SI1gPGd5sJ_/view).
It must:

1. Accept four command line arguments:
    1. The path to a file containing a PMP configuration.
    2. A physical address in hexadecimal, with a leading '0x'.
    3. A privilege mode (one of 'M', 'S', or 'U').
    4. An operation (one of 'R' (read), 'W' (write), or 'X' (execute/fetch).
2. For the given physical address and privilege mode, print whether or not the address would cause an access fault.

The PMP configuration file will be a text file with 128 lines. The first 64 lines will contain the contents of pmpNcfg (for N = 0..63) as a hexadecimal integer. (NOTE: *not* pmpcfgN)
The last 64 lines will contain the contents of pmpaddrN (for N = 0..63).

Example invocation:

```
program pmp_configuration.txt 0xdeadbeef M R
```

Example configuration file:

```
0x0
0x1
(... 62 more lines)
0x8000000
0x100000000
(... 62 more lines)
```

# Submission

To submit your entry, create a Pull Request against this repository (https://github.com/dhower-qc/idl-programming-challenge.git) that:

- Contains your submission in a new directory under `submissions` named after your GitHub username. For example, `submissions/dhower-qc`.
- Contains instructions on how to build your program, if needed (i.e., if using a compiled language).

You will need to create a fork of this repository. See https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork for more information.

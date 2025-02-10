# PMP Checker

This is a simple Python script that simulates a RISC-V Physical Memory Protection (PMP) check. It reads a PMP configuration from a text file and then checks whether a given physical address would be allowed for a specified privilege mode and access type.

## Overview

- **PMP Configuration:** The config file contains 128 lines. The first 64 lines are configuration bytes - one per PMP entry that define permissions (read, write, execute), address matching mode (TOR, NA4, or NAPOT), and whether the entry is locked. The next 64 lines are the corresponding PMP address registers.
- **Access Check:** The script goes through each active PMP entry, computes the effective address range, and then determines if the given physical address falls into one of these regions. If it does, the appropriate permission is checked.
- **Privilege Modes:** Machine mode (`M`) typically bypasses PMP checks unless the entry is locked. Supervisor (`S`) and User (`U`) modes follow the PMP rules strictly.

## Files

- **pmp_check.py:** The main script that reads the configuration file, parses the command-line arguments, and prints whether the access is allowed or not.
- **pmp_config.txt:** A sample configuration file. In this sample, only the first PMP entry is active (using TOR mode with read enabled), while the other entries are disabled.


## Example Usage

   ```./pmp_check.py pmp_config.txt 0x3000 S R ```

   Output : 

   ``` Access Allowed ```


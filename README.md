# Basic Buffer Overflow - VulnServer TRUN

A step-by-step walkthrough of exploiting the TRUN command buffer overflow vulnerability in VulnServer.

![Buffer Overflow](https://img.shields.io/badge/Security-Buffer%20Overflow-red)
![Windows Exploitation](https://img.shields.io/badge/Platform-Windows-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Beginner-green)

## Overview

This project demonstrates a classic buffer overflow vulnerability exploitation in the VulnServer application, specifically targeting the TRUN command. The walkthrough covers the entire process from discovery to exploitation, making it suitable for beginners learning about memory corruption vulnerabilities.

## Prerequisites

- Windows machine (for running VulnServer)
- Kali Linux (or WSL with Kali) for exploitation tools
- Immunity Debugger
- Mona.py script (for Immunity Debugger)
- Python 3
- Basic understanding of TCP/IP networking

## Tools Used

- VulnServer - Intentionally vulnerable Windows TCP server
- Immunity Debugger - Windows debugger for analyzing memory
- SPIKE Fuzzer - Network protocol fuzzer
- Mona.py - Python script for Immunity Debugger that assists with exploit development
- Metasploit Framework - For generating shellcode

## Installation

1. Download VulnServer and extract it to a directory on your Windows machine
2. Install Immunity Debugger
3. Download mona.py and place it in the PyCommands folder of Immunity Debugger
   ```
   C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\
   ```

## Exploitation Process

The buffer overflow exploitation follows these key steps:

1. **Discovery and Fuzzing**: Using SPIKE to identify the vulnerable TRUN command
2. **Crash Replication**: Creating a Python script to consistently trigger the crash
3. **Controlling EIP**: Finding the exact offset to control the instruction pointer
4. **Finding Bad Characters**: Identifying bytes that might disrupt the exploit
5. **Finding a JMP ESP Instruction**: Locating a reliable address to jump to shellcode
6. **Creating Shellcode**: Generating a reverse shell payload
7. **Exploitation**: Combining all elements to achieve code execution

## Detailed Walkthrough

### 1. Fuzzing with SPIKE

Create a fuzzer.spk file:

```
s_readline();
s_string("TRUN ");
s_string_variable("FUZZ");
```

Run the fuzzer against VulnServer to identify potential buffer overflow:

```bash
generic_send_tcp [VulnServer_IP] 9999 fuzzer.spk 0 0
```

### 2. Crash Replication Script

Initial Python script to replicate the crash:

```python

```

### 3. Finding the EIP Offset

Generate a unique pattern and locate the EIP offset:

Update the script to target the exact EIP offset (2003 bytes):

### 4. Finding Bad Characters

Test all possible characters to identify those that cause issues:

### 5. Finding JMP ESP

Use mona.py to find a reliable JMP ESP instruction:

```
!mona jmp -r esp
```

### 6. Generating Shellcode

Create a reverse shell payload with msfvenom:


### 7. Final Exploit

Complete exploit script:

## Usage

1. Start VulnServer on the Windows machine
2. Start Immunity Debugger and attach to VulnServer.exe
3. Set up a netcat listener: `nc -lvnp 4444`
4. Run the exploit script: `python3 exploit.py`
5. Receive a reverse shell connection

## Resources


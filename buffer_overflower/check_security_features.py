import os
import subprocess

def compile_c_code(c_file_path, output_path, compile_args):
    """Helper function to compile C code"""
    print(f"  Compiling: {output_path} (options: {' '.join(compile_args)})")
    compile_cmd = ["gcc", c_file_path, "-o", output_path] + compile_args
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Compilation error:\n{result.stderr}")
        return False, result.stderr
    print(f"  Compilation successful: {output_path}")
    return True, ""

def run_program_with_payload(exe_path, payload):
    """Helper function to run the generated binary with a payload and get the output (passed as standard input)"""
    print(f"  Running: {exe_path}")
    
    # --- This is the modification point ---
    # Since the payload is in bytes format, write it to a temporary file and redirect it as standard input
    temp_payload_file = "temp_payload.bin"
    with open(temp_payload_file, "wb") as f:
        f.write(payload)
    
    # Construct the execution command and redirect standard input
    run_cmd = [exe_path] # Pass only the program name
    
    # Generate a file object with open() and pass it to the stdin argument
    with open(temp_payload_file, 'rb') as f_stdin:
        process = subprocess.Popen(run_cmd, stdin=f_stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate() # Perform communication here

    # Delete temp_payload_file
    os.remove(temp_payload_file)

    print(f"  Exit code: {process.returncode}")
    print(f"  stdout:\n{stdout.decode('utf-8', errors='ignore').strip()}")
    print(f"  stderr:\n{stderr.decode('utf-8', errors='ignore').strip()}")
    return process.returncode, stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore')

def check_ssp_fortify():
    """Determine the effectiveness of SSP and FORTIFY_SOURCE"""

    c_file_path = "overflow.c"

    results = {}
    # Payload to cause overflow (read from exploit.bin)
    payload_path = "exploit.bin"
    with open(payload_path, "rb") as f:  # Read in binary mode
        overflow_payload = f.read()

    # --- SSP (Stack Smashing Protector) determination ---
    print("\n=== SSP (Stack Smashing Protector) determination ===")
    ssp_enabled_exe = "./ssp_enabled_test"
    ssp_disabled_exe = "./ssp_disabled_test"
    
    # Compile with SSP enabled (-fstack-protector-all)
    ssp_enabled_compile_args = ["-fstack-protector-all", "-no-pie"] # Disable PIE for simplicity
    success, _ = compile_c_code(c_file_path, ssp_enabled_exe, ssp_enabled_compile_args)
    if success:
        return_code, stdout, stderr = run_program_with_payload(ssp_enabled_exe, overflow_payload)
        # If SSP detects it, it usually outputs a message to stderr and exits with SIGABRT (exit code 134)
        if "*** stack smashing detected ***" in stderr or return_code == 134:
            results["SSP_ENABLED"] = "Enabled"
            print("  Result: SSP is likely enabled (stack smashing detected message or SIGABRT).")
        else:
            results["SSP_ENABLED"] = "Disabled"
            print(f"  Result: SSP is disabled or not detecting as expected (exit code: {return_code}).")
    else:
        results["SSP_ENABLED"] = "Undetermined (compilation failed)"
        print("  Result: Cannot determine because compilation failed with SSP enabled.")

    # Compile with SSP disabled (-fno-stack-protector)
    ssp_disabled_compile_args = ["-fno-stack-protector", "-no-pie"]
    success, _ = compile_c_code(c_file_path, ssp_disabled_exe, ssp_disabled_compile_args)
    if success:
        return_code, stdout, stderr = run_program_with_payload(ssp_disabled_exe, overflow_payload)
        # If SSP is disabled, the overflow should cause a Segmentation Fault (SIGSEGV, exit code 139)
        if "*** stack smashing detected ***" not in stderr and return_code == 139:
            results["SSP_DISABLED"] = "Disabled"
            print("  Result: SSP is likely disabled (SIGSEGV without stack smashing detected message).")
        else:
            results["SSP_DISABLED"] = "Unknown or unexpected behavior"
            print(f"  Result: Despite SSP being disabled, the expected SIGSEGV did not occur (exit code: {return_code}).")
    else:
        results["SSP_DISABLED"] = "Undetermined (compilation failed)"
        print("  Result: Cannot determine because compilation failed with SSP disabled.")


    # --- Automatic Fortification (FORTIFY_SOURCE) determination ---
    print("\n=== Automatic Fortification (FORTIFY_SOURCE) determination ===")
    fortify_enabled_exe = "./fortify_enabled_test"
    fortify_disabled_exe = "./fortify_disabled_test"

    # Compile with FORTIFY_SOURCE enabled (-D_FORTIFY_SOURCE=2)
    fortify_enabled_compile_args = ["-D_FORTIFY_SOURCE=2", "-no-pie"]
    success, compile_stderr_fortify = compile_c_code(c_file_path, fortify_enabled_exe, fortify_enabled_compile_args)
    if success:
        return_code, stdout, stderr = run_program_with_payload(fortify_enabled_exe, overflow_payload)
        # FORTIFY_SOURCE causes a runtime error or a compile-time warning/error
        if "buffer overflow detected" in stderr or "Aborted" in stderr or return_code == 134: # Also consider SIGABRT
            results["FORTIFY_SOURCE_ENABLED"] = "Enabled"
            print("  Result: FORTIFY_SOURCE is likely enabled (runtime error or abnormal termination).")
        elif "warning: call to" in compile_stderr_fortify and "_chk" in compile_stderr_fortify: # Compile-time warning is also considered detection
             results["FORTIFY_SOURCE_ENABLED"] = "Enabled (with compilation warning)"
             print("  Result: FORTIFY_SOURCE is likely enabled (dangerous function call warning during compilation).")
        else:
            results["FORTIFY_SOURCE_ENABLED"] = "Disabled"
            print(f"  Result: FORTIFY_SOURCE is disabled or not detecting as expected (exit code: {return_code}).")
    else:
        results["FORTIFY_SOURCE_ENABLED"] = "Undetermined (compilation failed)"
        print("  Result: Cannot determine because compilation failed with FORTIFY_SOURCE enabled.")

    # Compile with FORTIFY_SOURCE disabled (no option)
    fortify_disabled_compile_args = ["-no-pie"] # PIE remains disabled
    success, _ = compile_c_code(c_file_path, fortify_disabled_exe, fortify_disabled_compile_args)
    if success:
        return_code, stdout, stderr = run_program_with_payload(fortify_disabled_exe, overflow_payload)
        # If FORTIFY_SOURCE is disabled, the overflow should cause a Segmentation Fault (SIGSEGV, exit code 139)
        if "buffer overflow detected" not in stderr and "Aborted" not in stderr and return_code == 139:
            results["FORTIFY_SOURCE_DISABLED"] = "Disabled"
            print("  Result: FORTIFY_SOURCE is likely disabled (SIGSEGV without runtime error).")
        else:
            results["FORTIFY_SOURCE_DISABLED"] = "Unknown or unexpected behavior"
            print(f"  Result: Despite FORTIFY_SOURCE being disabled, the expected SIGSEGV did not occur (exit code: {return_code}).")
    else:
        results["FORTIFY_SOURCE_DISABLED"] = "Undetermined (compilation failed)"
        print("  Result: Cannot determine because compilation failed with FORTIFY_SOURCE disabled.")


    # --- Cleanup temporary files ---
    if os.path.exists(ssp_enabled_exe): os.remove(ssp_enabled_exe)
    if os.path.exists(ssp_disabled_exe): os.remove(ssp_disabled_exe)
    if os.path.exists(fortify_enabled_exe): os.remove(fortify_enabled_exe)
    if os.path.exists(fortify_disabled_exe): os.remove(fortify_disabled_exe)

    print("\n=== Final verdict ===")
    if results.get("SSP_ENABLED") == "Enabled" and results.get("SSP_DISABLED") in ["Disabled", "Unknown or unexpected behavior"]: # SEGV is OK for SSP disabled result
        print("→ **SSP (Stack Smashing Protector) appears to be functioning properly.**")
    else:
        print("→ **The status of SSP (Stack Smashing Protector) is unknown or unstable.**")

    if results.get("FORTIFY_SOURCE_ENABLED") == "Enabled" and results.get("FORTIFY_SOURCE_DISABLED") in ["Disabled", "Unknown or unexpected behavior"]: # SEGV is OK for FORTIFY disabled result
        print("→ **Automatic Fortification (FORTIFY_SOURCE) appears to be functioning properly.**")
    else:
        print("→ **The status of Automatic Fortification (FORTIFY_SOURCE) is unknown or unstable.**")


if __name__ == "__main__":
    print("--- Security mechanism effectiveness determination program ---")
    print("This program tests the effectiveness of SSP and FORTIFY_SOURCE.")
    print("gcc compiler must be installed.")
    check_ssp_fortify()

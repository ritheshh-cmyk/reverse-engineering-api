import subprocess

def run_radare2(path):
    try:
        output = subprocess.check_output(["radare2", "-c", "aaa;afl", "-q0", path])
        return output.decode()
    except Exception as e:
        return f"Radare2 Error: {str(e)}"

import subprocess

def run_floss(path):
    try:
        output = subprocess.check_output(["floss", path])
        return output.decode()
    except Exception as e:
        return f"Floss Error: {str(e)}"

import subprocess

def run(target):
    """
    Executa Nikto contra o target e retorna a saída.
    """
    try:
        proc = subprocess.run(['nikto', '-h', target],
                              capture_output=True, text=True, timeout=120)
        return proc.stdout
    except Exception as e:
        return f"Error: {e}"
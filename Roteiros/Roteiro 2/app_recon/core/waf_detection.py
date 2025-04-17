import subprocess

def run(url):
    """
    Executa o utilitário wafw00f via subprocess e retorna a saída.
    """
    try:
        proc = subprocess.run(['wafw00f', url], capture_output=True, text=True, timeout=30)
        return proc.stdout
    except Exception as e:
        return f"Error: {e}"
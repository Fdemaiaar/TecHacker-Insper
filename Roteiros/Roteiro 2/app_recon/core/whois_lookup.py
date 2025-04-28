# core/whois_lookup.py

import subprocess

def run(domain):
    """
    Executa o comando 'whois' via subprocess e retorna a saída.
    """
    try:
        proc = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Retorna stdout se houver, senão stderr (mensagens de erro do whois)
        return proc.stdout or proc.stderr
    except Exception as e:
        return f"Error: {e}"

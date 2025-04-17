import whois

def run(domain):
    """
    Retorna dados WHOIS do domínio.
    """
    try:
        w = whois.whois(domain)
        return w.text
    except Exception as e:
        return f"Error: {e}"
import dns.resolver

def run(domain):
    """
    Realiza consultas DNS (NS, MX, A) usando dnspython.
    Retorna string formatada com resultados.
    """
    output = []
    try:
        output.append('Name Servers:')
        for r in dns.resolver.resolve(domain, 'NS'):
            output.append(str(r.target))
        output.append('\nMail Servers:')
        for r in dns.resolver.resolve(domain, 'MX'):
            output.append(str(r.exchange))
        output.append('\nA Records:')
        for r in dns.resolver.resolve(domain, 'A'):
            output.append(str(r.address))
    except Exception as e:
        output.append(f'Error: {e}')
    return '\n'.join(output)
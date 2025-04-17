from sublist3r import main as sublist3r_main

def run(domain):
    """
    Descobre subdomínios usando Sublist3r.
    Se falhar na extração de token ou outro erro, retorna mensagem clara.
    """
    try:
        subs = sublist3r_main(domain, 40, savefile=None, ports=None,
                               silent=True, verbose=False,
                               enable_bruteforce=False, engines=None)
        if not subs:
            return "Nenhum subdomínio encontrado."
        return "\n".join(subs)
    except IndexError:
        return "Erro: falha ao extrair token CSRF do Sublist3r."
    except Exception as e:
        return f"Erro inesperado na enumeração de subdomínios: {e}"

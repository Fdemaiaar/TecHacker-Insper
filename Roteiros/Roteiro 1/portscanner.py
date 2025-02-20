import socket
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

# Dicionário com portas well-known e seus serviços associados, enriquecido conforme os testes (nmap)
WELL_KNOWN_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    135: "MSRPC",
    139: "NetBIOS-SSN",
    445: "Microsoft-DS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    1309: "tcpwrapped"
}

def get_socket_family(ip):
    """
    Determina a família do socket (IPv4 ou IPv6) com base no endereço IP informado.
    Se o endereço contiver ':' assume-se IPv6, senão IPv4.
    """
    if ':' in ip:
        return socket.AF_INET6
    else:
        return socket.AF_INET

def scan_tcp(ip, port, family):
    """
    Realiza o escaneamento TCP em uma porta:
    - Tenta estabelecer conexão usando socket.connect_ex.
    - Se a conexão for bem-sucedida (resultado 0), considera a porta aberta e realiza banner grabbing.
    - Caso contrário, classifica a porta como "fechada ou filtrada".
    """
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            status = "aberta"
            try:
                # Banner grabbing: tenta capturar dados enviados logo após a conexão
                s.settimeout(2)
                banner = s.recv(1024)
                if banner:
                    banner_text = banner.decode('utf-8', errors='ignore').strip()
                else:
                    banner_text = "Nenhum banner recebido"
            except Exception:
                banner_text = "Banner não obtido"
        else:
            status = "fechada ou filtrada"
            banner_text = ""
    except Exception as e:
        status = f"erro: {str(e)}"
        banner_text = ""
    s.close()
    return status, banner_text

def scan_udp(ip, port, family):
    """
    Realiza o escaneamento UDP em uma porta:
    - Envia um pacote UDP vazio e aguarda uma resposta.
    - Se uma resposta for recebida, considera a porta aberta.
    - Caso ocorra timeout, classifica como "fechada ou filtrada".
    """
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(b'', (ip, port))
        data, addr = s.recvfrom(1024)
        status = "aberta (resposta recebida)"
        banner_text = data.decode('utf-8', errors='ignore').strip() if data else ""
    except socket.timeout:
        status = "fechada ou filtrada"
        banner_text = ""
    except Exception as e:
        status = f"erro: {str(e)}"
        banner_text = ""
    s.close()
    return status, banner_text

def start_scan():
    """
    Função acionada pelo botão "Iniciar Escaneamento":
    - Lê o IP, o intervalo de portas e o protocolo (TCP ou UDP) definidos na interface.
    - Para cada porta no intervalo informado, executa o escaneamento e exibe o status, o serviço associado
      (quando mapeado no dicionário WELL_KNOWN_PORTS) e o banner (se disponível).
    """
    ip = ip_entry.get().strip()
    port_range = port_entry.get().strip()
    protocol = protocol_var.get()
    
    try:
        start_port, end_port = map(int, port_range.split('-'))
    except:
        result_text.insert(tk.END, "Intervalo de portas inválido. Use o formato: 20-80\n")
        return
    
    family = get_socket_family(ip)
    
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Iniciando escaneamento em {ip} ({protocol}) de {start_port} até {end_port}...\n\n")
    
    for port in range(start_port, end_port + 1):
        if protocol == "TCP":
            status, banner = scan_tcp(ip, port, family)
        else:
            status, banner = scan_udp(ip, port, family)
        
        service = WELL_KNOWN_PORTS.get(port, "Serviço não identificado")
        result_text.insert(tk.END, f"Porta {port}: {status} - Serviço: {service}\n")
        if banner:
            result_text.insert(tk.END, f"   Banner: {banner}\n")
    
    result_text.insert(tk.END, "\nEscaneamento finalizado.\n")

# Criação da interface gráfica utilizando Tkinter
root = tk.Tk()
root.title("Port Scanner em Python")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(frame, text="Endereço IP:").grid(row=0, column=0, sticky=tk.W)
ip_entry = ttk.Entry(frame, width=30)
ip_entry.grid(row=0, column=1, sticky=tk.W)

ttk.Label(frame, text="Intervalo de Portas (ex: 20-80):").grid(row=1, column=0, sticky=tk.W)
port_entry = ttk.Entry(frame, width=30)
port_entry.grid(row=1, column=1, sticky=tk.W)

ttk.Label(frame, text="Protocolo:").grid(row=2, column=0, sticky=tk.W)
protocol_var = tk.StringVar(value="TCP")
tcp_radio = ttk.Radiobutton(frame, text="TCP", variable=protocol_var, value="TCP")
tcp_radio.grid(row=2, column=1, sticky=tk.W)
udp_radio = ttk.Radiobutton(frame, text="UDP", variable=protocol_var, value="UDP")
udp_radio.grid(row=2, column=1, padx=60, sticky=tk.W)

scan_button = ttk.Button(frame, text="Iniciar Escaneamento", command=start_scan)
scan_button.grid(row=3, column=0, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(root, width=80, height=20)
result_text.grid(row=1, column=0, padx=10, pady=10)

root.mainloop()

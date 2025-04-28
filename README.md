# app_recon - Roteiro 2

Ferramenta **GUI** de reconhecimento de alvos para testes de penetração, modular e extensível.  
Reúne os principais scripts de footprinting e reconnaissance em um único aplicativo.

---

## Visão Geral

O **app_recon** integra:

- **PortScan**: escaneamento TCP/UDP de portas, com banner grabbing e mapeamento de serviços well-known.  
- **WHOIS Lookup**: consulta de registros de domínio (registrante, DNS autoritativos, datas).  
- **DNS Enumeration**: enumeração de **NS**, **MX** e **A records** via `dnspython`.  
- **Subdomain Scan**: descoberta de subdomínios com **Sublist3r**, com tratamento de erro de CSRF.  
- **WAF Detection**: identificação de Web Application Firewalls chamando o utilitário `wafw00f`.  
- **Vulnerability Scan**: integração com **Nikto** para varredura de vulnerabilidades HTTP.

A interface principal é baseada em **Tkinter** (GUI com abas), mas mantemos um **CLI legado** (`cli.py`) para quem preferir linha de comando.

---

## Pré-requisitos de Sistema

No Debian/Ubuntu (ou derivados):

```bash
sudo apt update
sudo apt install python3-tk nikto dnsenum wafw00f
```

> **Nota:**  
> - O `python3-tk` é necessário para a interface gráfica Tkinter.  
> - `nikto`, `dnsenum` e `wafw00f` são utilizadas por subprocessos, não como pacotes Python.  

---

## Instalação das Dependências Python

1. Crie e ative um ambiente virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
1. Instale as bibliotecas do projeto:
   ```bash
   pip install -r requirements.txt
   ```


## Estrutura do Projeto

```bash
app_recon/
├── core/                  # Módulos de cada ferramenta
│   ├── __init__.py
│   ├── portscan.py
│   ├── whois_lookup.py
│   ├── dns_enum.py
│   ├── subdomain_scan.py
│   ├── waf_detection.py
│   └── vuln_scan.py
├── utils.py               # Logging unificado
├── gui.py                 # Interface gráfica Tkinter
├── requirements.txt       # Dependências Python
└── README.md              # Este documento
```

## Executando a GUI

Para iniciar a interface gráfica do `app_recon`, execute o seguinte comando no seu terminal:

```bash
python3 gui.py
```
ertifique-se de ter instalado todas as dependências listadas em `requirements.txt`.

## Exemplos de Uso e Saída

A seguir estão exemplos de como usar cada ferramenta através da GUI e o tipo de saída esperada.

### PortScan (Exemplo: TCP, Portas 20–25)

```sql
Port 20: closed/filtered (unknown)
Port 21: open (FTP)
  Banner: "220 (vsFTPd 3.0.3)"
Port 22: open (SSH)
  Banner: "SSH-2.0-OpenSSH_7.6p1"
...
```

### WHOIS Lookup (Exemplo: ekkopark.com.br)
```yaml
Domain Name: EKKOPARK.COM.BR
Registrar: Registro.br
Creation Date: 2010-05-12
Name Server: ns1.ekkopark.com.br
...
```

### DNS Enumeration (Exemplo: ekkopark.com.br)
```yaml
Name Servers:
  ns1.ekkopark.com.br
  ns2.ekkopark.com.br
Mail Servers:
  mail.ekkopark.com.br
A Records:
  203.0.113.10
...
```

### Subdomain Scan (Exemplo: ekkopark.com.br)
```bash
Carregando subdomínios...
[www.ekkopark.com](https://www.ekkopark.com).br
intranet.ekkopark.com.br
dev.ekkopark.com.br
...
```

### WAF Detection (Exemplo: http://ekkopark.com.br)
```bash
Carregando WAF detection...
Output of wafw00f...
(Saída detalhada da detecção do WAF)
...
```

### Vulnerability Scan (Exemplo: Nikto, Alvo 192.168.0.10)
```Diff
Carregando vulnerabilidades...
- Nikto v2.1.6
+ Target IP: 192.168.0.10
+ Server: Apache/2.4.41 (Ubuntu)
+ OSVDB-3102: /admin/: Directory indexing found.
...
```

## Arquitetura e Design

* **Modularidade**: Cada ferramenta de reconhecimento reside em seu próprio módulo dentro do diretório `core/`. Cada módulo expõe uma função principal, como `run(...)`, para ser chamada pela GUI.
* **Interface**: A interface gráfica do usuário (GUI) é construída usando `tkinter`, a biblioteca padrão de GUI do Python. As diferentes ferramentas são organizadas usando um widget Notebook (abas) para facilitar a navegação.
* **Logging**: Todas as operações importantes e erros são registrados no arquivo `app_recon.log`. Isso é gerenciado de forma centralizada pela função `log()` no módulo `utils.py`.
* **Tratamento de Erros**: O aplicativo tenta lidar com erros de forma graciosa, fornecendo feedback claro ao usuário. Isso inclui fallbacks e mensagens específicas para falhas conhecidas (por exemplo, um erro de CSRF ao usar o `Sublist3r` para a varredura de subdomínios).
* **Loading Indicators**: Indicadores visuais como “Carregando…” são exibidos na GUI antes de iniciar operações que podem levar mais tempo para serem concluídas, melhorando a experiência do usuário.

## Contribuição

Pull requests são bem-vindos! Sinta-se à vontade para corrigir bugs, melhorar a interface do usuário ou sugerir e implementar novos módulos de ferramentas (por exemplo, integração com `masscan`, `sslyze`, etc.).

1.  Faça um Fork do repositório.
2.  Crie uma branch para sua feature (`git checkout -b feature/nova-ferramenta`).
3.  Faça commit de suas mudanças (`git commit -am 'Adiciona nova ferramenta X'`).
4.  Faça push para a branch (`git push origin feature/nova-ferramenta`).
5.  Abra um Pull Request.
import socket

def run(target, port_range, protocol):
    """
    Escaneia portas TCP ou UDP.
    target: IP ou domínio
    port_range: 'start-end'
    protocol: 'TCP' ou 'UDP'
    Retorna lista de tuplas: (porta, status, banner, service)
    """
    WELL_KNOWN = {
        22: "SSH", 80: "HTTP", 443: "HTTPS",
        135: "MSRPC", 139: "NetBIOS-SSN", 445: "Microsoft-DS",
        3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
        1309: "tcpwrapped"
    }

    def get_family(ip):
        return socket.AF_INET6 if ':' in ip else socket.AF_INET

    def scan_tcp(ip, port, family):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            res = s.connect_ex((ip, port))
            if res == 0:
                status = 'open'
                s.settimeout(2)
                try:
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    banner = ''
            else:
                status = 'closed/filtered'
                banner = ''
        except Exception:
            status, banner = 'error', ''
        s.close()
        return status, banner

    def scan_udp(ip, port, family):
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(b'', (ip, port))
            data, _ = s.recvfrom(1024)
            status = 'open'
            banner = data.decode('utf-8', errors='ignore').strip() if data else ''
        except socket.timeout:
            status, banner = 'closed/filtered', ''
        except Exception:
            status, banner = 'error', ''
        s.close()
        return status, banner

    start, end = map(int, port_range.split('-'))
    family = get_family(target)
    results = []
    for port in range(start, end + 1):
        if protocol.upper() == 'TCP':
            status, banner = scan_tcp(target, port, family)
        else:
            status, banner = scan_udp(target, port, family)
        service = WELL_KNOWN.get(port, 'unknown')
        results.append((port, status, banner, service))
    return results
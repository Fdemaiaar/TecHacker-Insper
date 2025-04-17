import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from core import portscan, whois_lookup, dns_enum, subdomain_scan, waf_detection, vuln_scan
from utils import log

class ReconApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('App Reconhecimento do Alvo')
        self.geometry('800x600')
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True)

        # PortScan Tab
        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text='PortScan')
        self.build_portscan_tab(tab1)

        # WHOIS Tab
        tab2 = ttk.Frame(notebook)
        notebook.add(tab2, text='WHOIS Lookup')
        self.build_whois_tab(tab2)

        # DNS Enum Tab
        tab3 = ttk.Frame(notebook)
        notebook.add(tab3, text='DNS Enumeration')
        self.build_dns_tab(tab3)

        # Subdomain Tab
        tab4 = ttk.Frame(notebook)
        notebook.add(tab4, text='Subdomain Scan')
        self.build_subdomain_tab(tab4)

        # WAF Tab
        tab5 = ttk.Frame(notebook)
        notebook.add(tab5, text='WAF Detection')
        self.build_waf_tab(tab5)

        # Vulnerability Tab
        tab6 = ttk.Frame(notebook)
        notebook.add(tab6, text='Vulnerability Scan')
        self.build_vuln_tab(tab6)

    def build_portscan_tab(self, frame):
        ttk.Label(frame, text='Target (IP/Domain):').grid(row=0, column=0)
        ip_entry = ttk.Entry(frame)
        ip_entry.grid(row=0, column=1)
        ttk.Label(frame, text='Port Range (ex: 1-100):').grid(row=1, column=0)
        port_entry = ttk.Entry(frame)
        port_entry.grid(row=1, column=1)
        ttk.Label(frame, text='Protocol:').grid(row=2, column=0)
        proto = tk.StringVar(value='TCP')
        ttk.Radiobutton(frame, text='TCP', variable=proto, value='TCP').grid(row=2, column=1)
        ttk.Radiobutton(frame, text='UDP', variable=proto, value='UDP').grid(row=2, column=2)
        btn = ttk.Button(frame, text='Run', command=lambda: self.run_portscan(ip_entry.get(), port_entry.get(), proto.get()))
        btn.grid(row=3, column=0, columnspan=3)
        txt = scrolledtext.ScrolledText(frame)
        txt.grid(row=4, column=0, columnspan=3, sticky='nsew')
        frame.grid_rowconfigure(4, weight=1)
        frame.grid_columnconfigure((0,1,2), weight=1)
        self.portscan_widgets = (ip_entry, port_entry, proto, txt)

    def run_portscan(self, target, prange, protocol):
        ip_e, port_e, proto_v, txt = self.portscan_widgets
        try:
            results = portscan.run(target, prange, protocol)
            txt.delete('1.0', tk.END)
            for port, status, banner, service in results:
                line = f'Port {port}: {status} ({service})\n'
                txt.insert(tk.END, line)
                if banner:
                    txt.insert(tk.END, f'  Banner: {banner}\n')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def build_whois_tab(self, frame):
        ttk.Label(frame, text='Domain:').grid(row=0, column=0)
        dom = ttk.Entry(frame)
        dom.grid(row=0, column=1)
        btn = ttk.Button(frame, text='Run', command=lambda: self.run_whois(dom.get()))
        btn.grid(row=1, column=0, columnspan=2)
        txt = scrolledtext.ScrolledText(frame)
        txt.grid(row=2, column=0, columnspan=2, sticky='nsew')
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure((0,1), weight=1)
        self.whois_widgets = (dom, txt)

    def run_whois(self, domain):
        dom, txt = self.whois_widgets
        out = whois_lookup.run(domain)
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, out)

    def build_dns_tab(self, frame):
        ttk.Label(frame, text='Domain:').grid(row=0, column=0)
        dom = ttk.Entry(frame)
        dom.grid(row=0, column=1)
        btn = ttk.Button(frame, text='Run', command=lambda: self.run_dns(dom.get()))
        btn.grid(row=1, column=0, columnspan=2)
        txt = scrolledtext.ScrolledText(frame)
        txt.grid(row=2, column=0, columnspan=2, sticky='nsew')
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure((0,1), weight=1)
        self.dns_widgets = (dom, txt)

    def run_dns(self, domain):
        dom, txt = self.dns_widgets
        out = dns_enum.run(domain)
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, out)

    def build_subdomain_tab(self, frame):
        ttk.Label(frame, text='Domain:').grid(row=0, column=0)
        dom = ttk.Entry(frame)
        dom.grid(row=0, column=1)
        btn = ttk.Button(frame, text='Run', command=lambda: self.run_sub(dom.get()))
        btn.grid(row=1, column=0, columnspan=2)
        txt = scrolledtext.ScrolledText(frame)
        txt.grid(row=2, column=0, columnspan=2, sticky='nsew')
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure((0,1), weight=1)
        self.sub_widgets = (dom, txt)

    def run_sub(self, domain):
        dom_entry, txt = self.sub_widgets
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, "Carregando subdomínios...\n")
        self.update_idletasks()    # força refresh da GUI

        out = subdomain_scan.run(domain)
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, out)

    def build_waf_tab(self, frame):
        ttk.Label(frame, text='URL:').grid(row=0, column=0)
        url = ttk.Entry(frame)
        url.grid(row=0, column=1)
        btn = ttk.Button(frame, text='Run', command=lambda: self.run_waf(url.get()))
        btn.grid(row=1, column=0, columnspan=2)
        txt = scrolledtext.ScrolledText(frame)
        txt.grid(row=2, column=0, columnspan=2, sticky='nsew')
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure((0,1), weight=1)
        self.waf_widgets = (url, txt)

    def run_waf(self, url):
        u, txt = self.waf_widgets
        out = waf_detection.run(url)
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, out)

    def build_vuln_tab(self, frame):
        ttk.Label(frame, text='Target:').grid(row=0, column=0)
        tgt = ttk.Entry(frame)
        tgt.grid(row=0, column=1)
        btn = ttk.Button(frame, text='Run', command=lambda: self.run_vuln(tgt.get()))
        btn.grid(row=1, column=0, columnspan=2)
        txt = scrolledtext.ScrolledText(frame)
        txt.grid(row=2, column=0, columnspan=2, sticky='nsew')
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure((0,1), weight=1)
        self.vuln_widgets = (tgt, txt)

    def run_vuln(self, target):
        tgt, txt = self.vuln_widgets
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, "Carregando vulnerabilidades... (isso pode demorar)\n")
        self.update_idletasks()
        try:
            out = vuln_scan.run(target)
        except Exception as e:
            out = f"Erro durante scan de vulnerabilidades: {e}"
        txt.delete('1.0', tk.END)
        txt.insert(tk.END, out)

if __name__ == '__main__':
    app = ReconApp()
    app.mainloop()


#!/usr/bin/env python3
import subprocess
import platform
import tkinter as tk
import json

# ==================== CONFIG ====================
PROXY_IP = "10.0.0.232"         # Proxy server IP (MUST CHANGE)
WIN_INTERFACE = ""              # Windows NIC name, empty for auto-detect
MAC_SERVICE = ""                # Mac network service, empty for auto-detect
# ================================================

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')

class ProxySwitch:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PS")
        self.root.geometry("160x180")
        self.root.resizable(False, False)
        self.root.configure(bg="#2b2b2b")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        try:
            self.root.iconbitmap(default='')
        except:
            pass
        
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 160) // 2
        y = (self.root.winfo_screenheight() - 180) // 2
        self.root.geometry(f"160x180+{x}+{y}")
        
        self.on = False
        
        tk.Frame(self.root, height=20, bg="#2b2b2b").pack()
        
        self.canvas = tk.Canvas(self.root, width=120, height=120, 
                                bg="#2b2b2b", highlightthickness=0)
        self.canvas.pack()
        
        self.btn = self.canvas.create_oval(10, 10, 110, 110, fill="#555555", 
                                           outline="#404040", width=3)
        self.btn_text = self.canvas.create_text(60, 60, text="OFF", 
                                                font=("Arial", 18, "bold"), fill="#888888")
        
        self.canvas.tag_bind(self.btn, "<Button-1>", lambda e: self.toggle())
        self.canvas.tag_bind(self.btn_text, "<Button-1>", lambda e: self.toggle())
        self.canvas.tag_bind(self.btn, "<Enter>", self.on_hover)
        self.canvas.tag_bind(self.btn, "<Leave>", self.on_leave)
        self.canvas.tag_bind(self.btn_text, "<Enter>", self.on_hover)
        self.canvas.tag_bind(self.btn_text, "<Leave>", self.on_leave)
        
        self.msg = tk.Label(self.root, text="", font=("Arial", 8), 
                           bg="#2b2b2b", fg="#ff6b6b")
        self.msg.pack(pady=(5, 0))
        
        self.root.mainloop()

    def on_close(self):
        if self.on:
            try:
                self.disable_proxy()
            except:
                pass
        self.root.destroy()

    def on_hover(self, e):
        self.canvas.itemconfig(self.btn, fill="#45a049" if self.on else "#666666")

    def on_leave(self, e):
        self.canvas.itemconfig(self.btn, fill="#4CAF50" if self.on else "#555555")

    def toggle(self):
        self.on = not self.on
        self.msg.config(text="")
        try:
            if self.on:
                self.enable_proxy()
                self.canvas.itemconfig(self.btn, fill="#4CAF50", outline="#45a049")
                self.canvas.itemconfig(self.btn_text, text="ON", fill="#ffffff")
            else:
                self.disable_proxy()
                self.canvas.itemconfig(self.btn, fill="#555555", outline="#404040")
                self.canvas.itemconfig(self.btn_text, text="OFF", fill="#888888")
        except Exception as e:
            self.on = not self.on
            self.msg.config(text=str(e)[:25])
            self.canvas.itemconfig(self.btn, fill="#e74c3c", outline="#c0392b")

    def run(self, cmd, sudo=False):
        if sudo and platform.system() == "Darwin":
            escaped = cmd.replace('\\', '\\\\').replace('"', '\\"')
            cmd = f'''osascript -e 'do shell script "{escaped}" with administrator privileges' '''
        r = run_cmd(cmd)
        if r.returncode != 0 and not sudo:
            raise Exception(f"Failed: {r.stderr[:50]}")
        return r

    def enable_proxy(self):
        if platform.system() == "Windows":
            iface = WIN_INTERFACE or self.get_win_interface()
            ip, mask = self.get_win_current_ip(iface)
            self.run(f'netsh interface ip set address name="{iface}" static {ip} {mask} {PROXY_IP}')
            run_cmd(f'netsh interface ip set dns name="{iface}" static {PROXY_IP}')
        else:
            svc = MAC_SERVICE or self.get_mac_service()
            ip, mask = self.get_mac_current_ip(svc)
            self.run(f'networksetup -setmanual "{svc}" {ip} {mask} {PROXY_IP}', sudo=True)
            self.run(f'networksetup -setdnsservers "{svc}" {PROXY_IP}', sudo=True)

    def disable_proxy(self):
        if platform.system() == "Windows":
            iface = WIN_INTERFACE or self.get_win_interface()
            self.run(f'netsh interface ip set address name="{iface}" dhcp')
            run_cmd(f'netsh interface ip set dns name="{iface}" dhcp')
        else:
            svc = MAC_SERVICE or self.get_mac_service()
            self.run(f'networksetup -setdhcp "{svc}"', sudo=True)
            self.run(f'networksetup -setdnsservers "{svc}" Empty', sudo=True)

    def get_win_interface(self):
        cmd = 'powershell -Command "Get-NetAdapter -Physical | Where-Object {$_.Status -eq \'Up\'} | Select-Object -First 1 -ExpandProperty Name"'
        r = run_cmd(cmd)
        name = r.stdout.strip()
        if not name:
            raise Exception("No active NIC")
        return name

    def get_win_current_ip(self, iface):
        cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \'{iface}\' -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength | ConvertTo-Json"'
        r = run_cmd(cmd)
        try:
            data = json.loads(r.stdout)
            if isinstance(data, list):
                data = data[0]
            return data["IPAddress"], self.prefix_to_mask(data["PrefixLength"])
        except:
            raise Exception("Cannot get IP")

    def prefix_to_mask(self, prefix):
        mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

    def get_mac_service(self):
        r = run_cmd("networksetup -listallnetworkservices")
        for line in r.stdout.splitlines()[1:]:
            svc = line.strip()
            if svc.startswith("*"):
                continue
            check = run_cmd(f'networksetup -getinfo "{svc}"')
            for l in check.stdout.splitlines():
                if l.startswith("IP address:") and l.split(":")[1].strip():
                    return svc
        raise Exception("No active network")

    def get_mac_current_ip(self, svc):
        r = run_cmd(f'networksetup -getinfo "{svc}"')
        ip, mask = None, None
        for line in r.stdout.splitlines():
            if line.startswith("IP address:"):
                ip = line.split(":", 1)[1].strip()
            elif line.startswith("Subnet mask:"):
                mask = line.split(":", 1)[1].strip()
        if not ip or not mask:
            raise Exception("Cannot get IP")
        return ip, mask

if __name__ == "__main__":
    ProxySwitch()

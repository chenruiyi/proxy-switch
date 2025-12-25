#!/usr/bin/env python3
import subprocess
import platform
import tkinter as tk
import json

# ==================== 配置区 ====================
PROXY_IP = "10.0.0.232"         # 代理服务器IP
WIN_INTERFACE = ""              # Windows网卡名，留空则自动检测（如"以太网"、"WLAN"）
MAC_SERVICE = ""                # Mac网络服务名，留空则自动检测（如"Wi-Fi"、"Ethernet"）
# ================================================

class ProxySwitch:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("代理切换")
        self.root.geometry("150x130")
        self.root.resizable(False, False)
        self.on = False
        self.msg = tk.Label(self.root, text="", font=("Arial", 9))
        self.msg.pack(pady=(10,0))
        self.btn = tk.Button(self.root, text="OFF", width=8, height=2, bg="gray",
                            command=self.toggle, font=("Arial", 14, "bold"))
        self.btn.pack(expand=True)
        self.root.mainloop()

    def toggle(self):
        self.on = not self.on
        self.msg.config(text="")
        try:
            if self.on:
                self.enable_proxy()
                self.btn.config(text="ON", bg="green")
            else:
                self.disable_proxy()
                self.btn.config(text="OFF", bg="gray")
        except Exception as e:
            self.on = not self.on  # 回滚状态
            self.msg.config(text=str(e)[:20])
            self.btn.config(bg="red")

    def run(self, cmd, sudo=False):
        if sudo and platform.system() == "Darwin":
            escaped = cmd.replace('\\', '\\\\').replace('"', '\\"')
            cmd = f'''osascript -e 'do shell script "{escaped}" with administrator privileges' '''
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if r.returncode != 0 and not sudo:
            raise Exception(f"命令执行失败")
        return r

    def enable_proxy(self):
        if platform.system() == "Windows":
            iface = WIN_INTERFACE or self.get_win_interface()
            ip, mask = self.get_win_current_ip(iface)
            self.run(f'netsh interface ip set address name="{iface}" static {ip} {mask} {PROXY_IP}')
            self.run(f'netsh interface ip set dns name="{iface}" static {PROXY_IP}')
        else:
            svc = MAC_SERVICE or self.get_mac_service()
            ip, mask = self.get_mac_current_ip(svc)
            self.run(f'networksetup -setmanual "{svc}" {ip} {mask} {PROXY_IP}', sudo=True)
            self.run(f'networksetup -setdnsservers "{svc}" {PROXY_IP}', sudo=True)

    def disable_proxy(self):
        if platform.system() == "Windows":
            iface = WIN_INTERFACE or self.get_win_interface()
            self.run(f'netsh interface ip set address name="{iface}" dhcp')
            self.run(f'netsh interface ip set dns name="{iface}" dhcp')
        else:
            svc = MAC_SERVICE or self.get_mac_service()
            self.run(f'networksetup -setdhcp "{svc}"', sudo=True)
            self.run(f'networksetup -setdnsservers "{svc}" Empty', sudo=True)

    def get_win_interface(self):
        cmd = 'powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object -First 1 -ExpandProperty Name"'
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        name = r.stdout.strip()
        if not name:
            raise Exception("未找到活动网卡")
        return name

    def get_win_current_ip(self, iface):
        cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \'{iface}\' -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength | ConvertTo-Json"'
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        try:
            data = json.loads(r.stdout)
            if isinstance(data, list):
                data = data[0]
            ip = data["IPAddress"]
            prefix = data["PrefixLength"]
            mask = self.prefix_to_mask(prefix)
            return ip, mask
        except:
            raise Exception("无法获取当前IP")

    def prefix_to_mask(self, prefix):
        mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

    def get_mac_service(self):
        r = subprocess.run("networksetup -listallnetworkservices", shell=True, capture_output=True, text=True)
        for line in r.stdout.splitlines()[1:]:
            svc = line.strip()
            if svc.startswith("*"):
                continue
            check = subprocess.run(f'networksetup -getinfo "{svc}"', shell=True, capture_output=True, text=True)
            if "IP address:" in check.stdout:
                for l in check.stdout.splitlines():
                    if l.startswith("IP address:") and l.split(":")[1].strip():
                        return svc
        raise Exception("未找到活动网络")

    def get_mac_current_ip(self, svc):
        r = subprocess.run(f'networksetup -getinfo "{svc}"', shell=True, capture_output=True, text=True)
        ip, mask = None, None
        for line in r.stdout.splitlines():
            if line.startswith("IP address:"):
                val = line.split(":", 1)[1].strip()
                if val:
                    ip = val
            elif line.startswith("Subnet mask:"):
                val = line.split(":", 1)[1].strip()
                if val:
                    mask = val
        if not ip or not mask:
            raise Exception("无法获取当前IP")
        return ip, mask

if __name__ == "__main__":
    ProxySwitch()

#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║         NETKIT — Network & Encode Tool   ║
╚══════════════════════════════════════════╝
A terminal toolkit: encoding, decoding, and network utilities.
"""

import base64
import binascii
import hashlib
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich import box
    RICH = True
except ImportError:
    RICH = False

if RICH:
    console = Console()
else:
    class _Console:
        def print(self, *a, **kw):
            import re as _re
            text = " ".join(str(x) for x in a)
            text = _re.sub(r'\[/?[^\]]*\]', '', text)
            print(text)
        def rule(self, title=""):
            print("─" * 60 + (f" {title} " if title else ""))
        def clear(self):
            os.system('cls' if platform.system() == 'Windows' else 'clear')
    console = _Console()

IS_WINDOWS = platform.system() == "Windows"

BANNER = r"""
  _   _  _____ _____ _  _____ _____ 
 | \ | || ____|_   _| |/ /_ _|_   _|
 |  \| ||  _|   | | | ' / | |  | |  
 | |\  || |___  | | | . \ | |  | |  
 |_| \_||_____| |_| |_|\_\___| |_|  
"""

def clear_screen():
    os.system('cls' if IS_WINDOWS else 'clear')

def header(title: str, subtitle: str = ""):
    clear_screen()
    if RICH:
        t = Text(BANNER, style="bold cyan")
        console.print(t)
        console.print(Panel(
            f"[bold white]{title}[/bold white]\n[dim]{subtitle}[/dim]" if subtitle else f"[bold white]{title}[/bold white]",
            border_style="cyan",
            padding=(0, 2)
        ))
    else:
        print(BANNER)
        print(f"\n  {'─'*50}")
        print(f"  {title}" + (f"  —  {subtitle}" if subtitle else ""))
        print(f"  {'─'*50}\n")

def success(msg):
    if RICH:
        console.print(f"[bold green]✓[/bold green] {msg}")
    else:
        print(f"[OK] {msg}")

def error(msg):
    if RICH:
        console.print(f"[bold red]✗[/bold red] {msg}")
    else:
        print(f"[ERR] {msg}")

def info(msg):
    if RICH:
        console.print(f"[bold cyan]→[/bold cyan] {msg}")
    else:
        print(f"[*] {msg}")

def warn(msg):
    if RICH:
        console.print(f"[bold yellow]![/bold yellow] {msg}")
    else:
        print(f"[WARN] {msg}")

def result_box(label: str, value: str):
    if RICH:
        console.print(Panel(
            f"[bold yellow]{value}[/bold yellow]",
            title=f"[bold cyan]{label}[/bold cyan]",
            border_style="dim",
            padding=(0, 1)
        ))
    else:
        print(f"\n  [{label}]")
        print(f"  {value}\n")

def prompt(text: str, default: str = "") -> str:
    if RICH:
        return Prompt.ask(f"[bold cyan]{text}[/bold cyan]", default=default) if default else Prompt.ask(f"[bold cyan]{text}[/bold cyan]")
    else:
        d = f" [{default}]" if default else ""
        return input(f"  {text}{d}: ").strip() or default

def menu_prompt(text: str) -> str:
    if RICH:
        return Prompt.ask(f"\n[bold white]{text}[/bold white]")
    else:
        return input(f"\n  {text}: ").strip()

def pause():
    input("\n  Press Enter to continue…")

def show_menu(title: str, options: list[tuple[str, str]]):
    """Display a numbered menu and return the chosen option key."""
    if RICH:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Key", style="bold cyan", width=4)
        table.add_column("Description", style="white")
        for key, desc in options:
            table.add_row(key, desc)
        console.print(table)
    else:
        for key, desc in options:
            print(f"  [{key}] {desc}")

def encode_menu():
    while True:
        header("ENCODING", "Transform your data into encoded formats")
        show_menu("Encoding", [
            ("1", "Base64 Encode"),
            ("2", "URL Encode"),
            ("3", "Hex Encode"),
            ("4", "Binary Encode"),
            ("5", "HTML Entity Encode"),
            ("6", "MD5 Hash"),
            ("7", "SHA-1 Hash"),
            ("8", "SHA-256 Hash"),
            ("9", "SHA-512 Hash"),
            ("0", "Back"),
        ])
        choice = menu_prompt("Select")
        if choice == "0":
            break
        elif choice == "1":
            data = prompt("Enter text to Base64 encode")
            result_box("Base64", base64.b64encode(data.encode()).decode())
        elif choice == "2":
            data = prompt("Enter text to URL encode")
            result_box("URL Encoded", urllib.parse.quote(data))
        elif choice == "3":
            data = prompt("Enter text to Hex encode")
            result_box("Hex", data.encode().hex())
        elif choice == "4":
            data = prompt("Enter text to Binary encode")
            binary = ' '.join(format(ord(c), '08b') for c in data)
            result_box("Binary", binary)
        elif choice == "5":
            data = prompt("Enter text to HTML encode")
            import html
            result_box("HTML Entities", html.escape(data))
        elif choice in ("6", "7", "8", "9"):
            data = prompt("Enter text to hash")
            algos = {"6": ("MD5", hashlib.md5), "7": ("SHA-1", hashlib.sha1),
                     "8": ("SHA-256", hashlib.sha256), "9": ("SHA-512", hashlib.sha512)}
            name, fn = algos[choice]
            result_box(name, fn(data.encode()).hexdigest())
        else:
            error("Invalid option.")
        pause()


def decode_menu():
    while True:
        header("DECODING", "Reverse-engineer encoded data")
        show_menu("Decoding", [
            ("1", "Base64 Decode"),
            ("2", "URL Decode"),
            ("3", "Hex Decode"),
            ("4", "Binary Decode"),
            ("5", "HTML Entity Decode"),
            ("0", "Back"),
        ])
        choice = menu_prompt("Select")
        if choice == "0":
            break
        elif choice == "1":
            data = prompt("Enter Base64 string")
            try:
                result_box("Decoded", base64.b64decode(data).decode(errors='replace'))
            except Exception as e:
                error(f"Decode failed: {e}")
        elif choice == "2":
            data = prompt("Enter URL-encoded string")
            result_box("URL Decoded", urllib.parse.unquote(data))
        elif choice == "3":
            data = prompt("Enter hex string (no spaces)").replace(" ", "").replace("0x", "")
            try:
                result_box("Hex Decoded", bytes.fromhex(data).decode(errors='replace'))
            except Exception as e:
                error(f"Decode failed: {e}")
        elif choice == "4":
            data = prompt("Enter binary string (space-separated bytes)")
            try:
                chars = [chr(int(b, 2)) for b in data.split()]
                result_box("Binary Decoded", ''.join(chars))
            except Exception as e:
                error(f"Decode failed: {e}")
        elif choice == "5":
            import html
            data = prompt("Enter HTML-encoded string")
            result_box("HTML Decoded", html.unescape(data))
        else:
            error("Invalid option.")
        pause()

def run_ping(host: str, count: int = 4) -> str:
    """Run a system ping and return output."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except FileNotFoundError:
        return "ping command not found on this system."

def tcp_connect_check(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def dns_lookup(host: str) -> dict:
    """Perform forward and reverse DNS lookup."""
    result = {}
    try:
        addr_info = socket.getaddrinfo(host, None)
        ips = list({info[4][0] for info in addr_info})
        result["ips"] = ips
        try:
            result["hostname"] = socket.gethostbyaddr(ips[0])[0]
        except Exception:
            result["hostname"] = "N/A"
    except socket.gaierror as e:
        result["error"] = str(e)
    return result

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def get_public_ip() -> str:
    """Try to get public IP using a socket trick (no HTTP lib needed)."""
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode()
    except Exception:
        return "Unavailable (check internet connection)"

def network_menu():
    while True:
        header("NETWORK TOOLS", "Diagnostics and recon utilities")
        show_menu("Network", [
            ("1", "Ping a Host"),
            ("2", "Port Scanner"),
            ("3", "DNS Lookup"),
            ("4", "Reverse DNS Lookup"),
            ("5", "Get Local IP Address"),
            ("6", "Get Public IP Address"),
            ("7", "Whois / Host Info"),
            ("8", "TCP Port Check (single)"),
            ("0", "Back"),
        ])
        choice = menu_prompt("Select")

        if choice == "0":
            break

        elif choice == "1":
            host = prompt("Host / IP to ping")
            count_str = prompt("Ping count", "4")
            try:
                count = int(count_str)
            except ValueError:
                count = 4
            info(f"Pinging {host} ({count} packets)…\n")
            output = run_ping(host, count)
            if RICH:
                console.print(Syntax(output, "text", theme="monokai", line_numbers=False, word_wrap=True))
            else:
                print(output)

        elif choice == "2":
            host = prompt("Host to scan")
            port_range = prompt("Port range (e.g. 1-1024 or 80,443,8080)", "1-1024")
            ports = []
            for part in port_range.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        a, b = part.split("-", 1)
                        ports.extend(range(int(a), int(b) + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        ports.append(int(part))
                    except ValueError:
                        pass
            if not ports:
                error("Invalid port range.")
                pause()
                continue
            info(f"Scanning {len(ports)} port(s) on {host}…\n")
            open_ports = []
            if RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task(f"Scanning {host}…", total=len(ports))
                    for port in ports:
                        if tcp_connect_check(host, port, timeout=0.5):
                            open_ports.append(port)
                        progress.advance(task)
            else:
                for i, port in enumerate(ports):
                    if tcp_connect_check(host, port, timeout=0.5):
                        open_ports.append(port)
                    if (i + 1) % 100 == 0:
                        print(f"  Scanned {i+1}/{len(ports)} ports…", end='\r')
                print()

            if open_ports:
                if RICH:
                    table = Table(title=f"Open Ports on {host}", box=box.SIMPLE_HEAVY, border_style="cyan")
                    table.add_column("Port", style="bold cyan", justify="right")
                    table.add_column("Service (guess)", style="dim")
                    common = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
                              80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
                              465:"SMTPS",587:"SMTP/TLS",993:"IMAPS",995:"POP3S",
                              3306:"MySQL",5432:"PostgreSQL",6379:"Redis",
                              8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"}
                    for p in open_ports:
                        table.add_row(str(p), common.get(p, "unknown"))
                    console.print(table)
                else:
                    print(f"\n  Open ports on {host}:")
                    for p in open_ports:
                        print(f"    {p}")
            else:
                warn("No open ports found in the given range.")

        elif choice == "3":
            host = prompt("Hostname / domain")
            info(f"Looking up {host}…")
            r = dns_lookup(host)
            if "error" in r:
                error(r["error"])
            else:
                if RICH:
                    table = Table(box=box.SIMPLE, show_header=False)
                    table.add_column("Key", style="bold cyan", width=20)
                    table.add_column("Value", style="white")
                    for ip in r.get("ips", []):
                        table.add_row("IP Address", ip)
                    table.add_row("Reverse Hostname", r.get("hostname", "N/A"))
                    console.print(table)
                else:
                    for ip in r.get("ips", []):
                        print(f"  IP:       {ip}")
                    print(f"  Hostname: {r.get('hostname', 'N/A')}")

        elif choice == "4":
            ip = prompt("IP address for reverse lookup")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result_box("Reverse DNS", hostname)
            except socket.herror as e:
                error(f"Reverse lookup failed: {e}")

        elif choice == "5":
            ip = get_local_ip()
            result_box("Local IP", ip)

        elif choice == "6":
            info("Fetching public IP…")
            ip = get_public_ip()
            result_box("Public IP", ip)

        elif choice == "7":
            host = prompt("Host / IP")
            try:
                ip = socket.gethostbyname(host)
                hostname = socket.getfqdn(host)
                result_box(f"Host Info — {host}", f"IP: {ip}\nFQDN: {hostname}")
            except Exception as e:
                error(str(e))

        elif choice == "8":
            host = prompt("Host / IP")
            port_str = prompt("Port")
            try:
                port = int(port_str)
                info(f"Checking {host}:{port}…")
                open_ = tcp_connect_check(host, port)
                if open_:
                    success(f"Port {port} is OPEN on {host}")
                else:
                    warn(f"Port {port} is CLOSED / filtered on {host}")
            except ValueError:
                error("Invalid port number.")
        else:
            error("Invalid option.")
        pause()

def conversion_menu():
    while True:
        header("CONVERSIONS", "Number bases, IP tools, and more")
        show_menu("Conversions", [
            ("1", "Number Base Converter (Dec / Hex / Oct / Bin)"),
            ("2", "IP to Integer / Integer to IP"),
            ("3", "CIDR to IP Range"),
            ("4", "Bytes ↔ Human Readable Size"),
            ("5", "Unix Timestamp ↔ Human Date"),
            ("0", "Back"),
        ])
        choice = menu_prompt("Select")
        if choice == "0":
            break

        elif choice == "1":
            raw = prompt("Enter a number (prefix: 0x=hex, 0b=binary, 0o=octal, plain=decimal)")
            try:
                n = int(raw, 0)
                if RICH:
                    table = Table(box=box.SIMPLE, show_header=False)
                    table.add_column("Base", style="bold cyan", width=15)
                    table.add_column("Value", style="yellow")
                    table.add_row("Decimal", str(n))
                    table.add_row("Hexadecimal", hex(n))
                    table.add_row("Octal", oct(n))
                    table.add_row("Binary", bin(n))
                    console.print(table)
                else:
                    print(f"  Dec: {n}\n  Hex: {hex(n)}\n  Oct: {oct(n)}\n  Bin: {bin(n)}")
            except ValueError:
                error("Could not parse the number.")

        elif choice == "2":
            mode = prompt("Direction: (1) IP→Int  (2) Int→IP", "1")
            if mode == "1":
                ip = prompt("Enter IPv4 address")
                try:
                    packed = socket.inet_aton(ip)
                    val = struct.unpack("!I", packed)[0]
                    result_box(f"{ip} → Integer", str(val))
                except Exception as e:
                    error(str(e))
            else:
                val = prompt("Enter integer")
                try:
                    packed = struct.pack("!I", int(val))
                    result_box(f"{val} → IP", socket.inet_ntoa(packed))
                except Exception as e:
                    error(str(e))

        elif choice == "3":
            cidr = prompt("Enter CIDR (e.g. 192.168.1.0/24)")
            try:
                ip_part, prefix = cidr.split("/")
                prefix = int(prefix)
                packed = struct.unpack("!I", socket.inet_aton(ip_part))[0]
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                network = packed & mask
                broadcast = network | (~mask & 0xFFFFFFFF)
                first = network + 1
                last = broadcast - 1
                count = max(0, broadcast - network - 1)

                def i2ip(i):
                    return socket.inet_ntoa(struct.pack("!I", i))

                if RICH:
                    table = Table(box=box.SIMPLE, show_header=False)
                    table.add_column("Field", style="bold cyan", width=18)
                    table.add_column("Value", style="yellow")
                    table.add_row("Network",    i2ip(network))
                    table.add_row("Broadcast",  i2ip(broadcast))
                    table.add_row("First Host",  i2ip(first))
                    table.add_row("Last Host",   i2ip(last))
                    table.add_row("Usable Hosts", f"{count:,}")
                    table.add_row("Subnet Mask", i2ip(mask))
                    console.print(table)
                else:
                    print(f"  Network:    {i2ip(network)}")
                    print(f"  Broadcast:  {i2ip(broadcast)}")
                    print(f"  First Host: {i2ip(first)}")
                    print(f"  Last Host:  {i2ip(last)}")
                    print(f"  Usable:     {count:,}")
            except Exception as e:
                error(f"Invalid CIDR: {e}")

        elif choice == "4":
            raw = prompt("Enter bytes value (e.g. 1048576)")
            try:
                n = int(raw)
                units = ["B", "KB", "MB", "GB", "TB", "PB"]
                val = float(n)
                u = 0
                while val >= 1024 and u < len(units) - 1:
                    val /= 1024
                    u += 1
                result_box("Human Readable", f"{val:.2f} {units[u]}")
            except ValueError:
                error("Invalid number.")

        elif choice == "5":
            mode = prompt("Direction: (1) Unix→Date  (2) Date→Unix", "1")
            if mode == "1":
                ts = prompt("Enter Unix timestamp")
                try:
                    dt = datetime.fromtimestamp(int(ts))
                    result_box("Date/Time", dt.strftime("%Y-%m-%d %H:%M:%S %Z"))
                except Exception as e:
                    error(str(e))
            else:
                d = prompt("Enter date (YYYY-MM-DD HH:MM:SS)", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                try:
                    dt = datetime.strptime(d, "%Y-%m-%d %H:%M:%S")
                    result_box("Unix Timestamp", str(int(dt.timestamp())))
                except Exception as e:
                    error(str(e))
        else:
            error("Invalid option.")
        pause()

def main():
    global RICH
    if not RICH:
        warn("'rich' not installed. Installing for a better experience…")
        ret = subprocess.run([sys.executable, "-m", "pip", "install", "rich", "-q"])
        if ret.returncode == 0:
            try:
                from rich.console import Console as _C
                from rich.panel import Panel as _P
                from rich.table import Table as _T
                from rich.text import Text as _Tx
                from rich.prompt import Prompt as _Pr
                from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
                from rich.syntax import Syntax as _S
                from rich import box as _box
                import importlib
                importlib.invalidate_caches()
                RICH = True
                info("'rich' installed successfully. Restart for full TUI experience.")
            except Exception:
                pass

    while True:
        header("NETKIT v1.0", f"Running on {platform.system()} {platform.release()}  |  {datetime.now().strftime('%H:%M:%S')}")

        if RICH:
            console.print()
            console.print("  [bold white]MAIN MENU[/bold white]\n")
        else:
            print("\n  MAIN MENU\n")

        show_menu("Main", [
            ("1", "Encoding"),
            ("2", "Decoding"),
            ("3", "Network Tools"),
            ("4", "Conversions"),
            ("5", "System Info"),
            ("0", "Exit"),
        ])

        choice = menu_prompt("Select module")

        if choice == "0":
            if RICH:
                console.print("\n[bold cyan]  Goodbye.[/bold cyan]\n")
            else:
                print("\n  Goodbye.\n")
            sys.exit(0)
        elif choice == "1":
            encode_menu()
        elif choice == "2":
            decode_menu()
        elif choice == "3":
            network_menu()
        elif choice == "4":
            conversion_menu()
        elif choice == "5":
            header("SYSTEM INFO")
            local_ip = get_local_ip()
            hostname = socket.gethostname()
            if RICH:
                table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
                table.add_column("Field", style="bold cyan", width=22)
                table.add_column("Value", style="white")
                table.add_row("Hostname",    hostname)
                table.add_row("OS",          f"{platform.system()} {platform.release()}")
                table.add_row("Architecture", platform.machine())
                table.add_row("Python",      sys.version.split()[0])
                table.add_row("Local IP",    local_ip)
                table.add_row("Time",        datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                console.print(table)
            else:
                print(f"  Hostname:  {hostname}")
                print(f"  OS:        {platform.system()} {platform.release()}")
                print(f"  Arch:      {platform.machine()}")
                print(f"  Python:    {sys.version.split()[0]}")
                print(f"  Local IP:  {local_ip}")
                print(f"  Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            pause()
        else:
            error("Invalid option. Choose 0–5.")
            time.sleep(1)

if __name__ == "__main__":
    main()

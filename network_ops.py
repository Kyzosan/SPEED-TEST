import subprocess
import socket
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import whois
import speedtest
import platform
from logger import app_logger
import time

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    app_logger.info(f"Local IP detected: {local_ip}")
    return local_ip

def get_public_ip(timeout=5):
    """
    Mendapatkan IP publik dari layanan eksternal.
    """
    endpoints = [
        ("https://ifconfig.me", lambda r: r.text.strip()),
        ("https://api.ipify.org?format=json", lambda r: r.json().get("ip")),
    ]
    for url, parser in endpoints:
        try:
            headers = {'User-Agent': 'curl/7.68.0'} if 'ifconfig' in url else {}
            r = requests.get(url, headers=headers, timeout=timeout)
            public_ip = parser(r)
            if public_ip and public_ip.replace('.', '').isdigit():
                app_logger.info(f"Public IP detected: {public_ip}")
                return public_ip
        except Exception as e:
            app_logger.warning(f"Failed to get public IP from {url}: {e}")
    app_logger.warning("Failed to detect public IP from all endpoints.")
    return None

def detect_ips(timeout=5):
    """
    Mendeteksi IP lokal dan publik secara paralel.
    """
    local, public = None, None
    def get_local():
        nonlocal local
        local = get_local_ip()

    def get_public():
        nonlocal public
        public = get_public_ip(timeout)

    local_thread = threading.Thread(target=get_local)
    public_thread = threading.Thread(target=get_public)

    local_thread.start()
    public_thread.start()

    local_thread.join()
    public_thread.join()

    return local, public

def ping_host(host, count=4, timeout=30):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, str(count), host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "❌ Ping command timed out."
    except Exception as e:
        return f"❌ Ping error: {e}"

def traceroute_host(host, timeout=60):
    try:
        cmd = ["traceroute", host] if platform.system().lower() != "windows" else ["tracert", host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "❌ Traceroute command timed out."
    except Exception as e:
        return f"❌ Traceroute error: {e}"

def scan_port(host, port, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((host, port))
        s.close()
        return port, result == 0
    except Exception:
        s.close()
        return port, False

def port_scan(host, start_port, end_port, max_threads=100, timeout_per_port=1):
    open_ports = []
    ports_to_scan = range(start_port, end_port + 1)
    app_logger.info(f"Scanning {len(ports_to_scan)} ports on {host} with {max_threads} threads.")
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout_per_port): port for port in ports_to_scan}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    app_logger.info(f"Port scan complete. Open ports: {sorted(open_ports)}")
    return sorted(open_ports)

def run_speedtest():
    try:
        st = speedtest.Speedtest()
        st.download()
        st.upload()
        results = st.results.dict()
        return {
            "download": f"{results['download'] / 1_000_000:.2f} Mbps",
            "upload": f"{results['upload'] / 1_000_000:.2f} Mbps",
            "ping": f"{results['ping']:.2f} ms"
        }
    except Exception as e:
        app_logger.error(f"Speedtest error: {e}")
        return {"error": f"❌ Speedtest error: {e}"}

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        app_logger.error(f"WHOIS lookup error for {domain}: {e}")
        return f"❌ WHOIS lookup error: {e}"
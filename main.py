import socket
import threading
import ipaddress
import queue
import time
import argparse
import sys

print_lock = threading.Lock()
task_queue = queue.Queue()

def tcp_ping(ip, timeout, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = (s.connect_ex((ip, port)) == 0)
        s.close()
        return ok
    except:
        return False

def scan_port(ip, port, timeout, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            results.append(port)
        s.close()
    except:
        pass

def port_worker(ip, ports_q, timeout, results):
    while True:
        try:
            port = ports_q.get_nowait()
        except queue.Empty:
            return
        scan_port(ip, port, timeout, results)
        ports_q.task_done()

def scan_ports(ip, start_port, end_port, timeout, threads):
    ports_q = queue.Queue()
    for p in range(start_port, end_port + 1):
        ports_q.put(p)

    results = []
    n = min(threads, ports_q.qsize())
    for _ in range(n):
        t = threading.Thread(target=port_worker, args=(ip, ports_q, timeout, results), daemon=True)
        t.start()

    ports_q.join()
    return sorted(results)

def network_worker(start_port, end_port, timeout, threads, ping_port):
    while True:
        try:
            ip = task_queue.get_nowait()
        except queue.Empty:
            return

        if tcp_ping(ip, timeout, ping_port):
            with print_lock:
                print(f"[+] Host up: {ip}")

            open_ports = scan_ports(ip, start_port, end_port, timeout, threads)

            with print_lock:
                if open_ports:
                    print(f"    Open ports on {ip}: {open_ports}")
                else:
                    print(f"    No open ports found on {ip}")

        task_queue.task_done()

def network_scan(cidr, start_port, end_port, timeout, threads, ping_port):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise SystemExit("Invalid CIDR. Example: 192.168.1.0/24")

    for ip in net.hosts():
        task_queue.put(str(ip))

    n = max(1, threads)
    for _ in range(n):
        t = threading.Thread(
            target=network_worker,
            args=(start_port, end_port, timeout, threads, ping_port),
            daemon=True
        )
        t.start()

    task_queue.join()

def parse_args():
    ap = argparse.ArgumentParser(description="Network + Port Scanner (TCP connect scan)")
    ap.add_argument("--cidr", help="Target network CIDR (e.g. 192.168.1.0/24)")
    ap.add_argument("--start", type=int, help="Start port")
    ap.add_argument("--end", type=int, help="End port")
    ap.add_argument("--timeout", type=float, default=0.5, help="Socket timeout seconds (default: 0.5)")
    ap.add_argument("--threads", type=int, default=200, help="Threads (default: 200)")
    ap.add_argument("--ping-port", type=int, default=80, help="Port used for TCP ping discovery (default: 80)")
    return ap.parse_args()

def need_prompt(v):
    return v is None

if __name__ == "__main__":
    args = parse_args()

    cidr = args.cidr
    start_port = args.start
    end_port = args.end
    timeout = args.timeout
    threads = args.threads
    ping_port = args.ping_port

    if need_prompt(cidr) or need_prompt(start_port) or need_prompt(end_port):
        if sys.stdin.isatty():
            print("=== Network + Port Scanner ===\n")
            if need_prompt(cidr):
                cidr = input("Target network (CIDR, e.g. 192.168.1.0/24): ").strip()
            if need_prompt(start_port):
                start_port = int(input("Start port: ").strip())
            if need_prompt(end_port):
                end_port = int(input("End port: ").strip())
        else:
            raise SystemExit(
                "No interactive input available. Run with args:\n"
                "python netscan.py --cidr 192.168.1.0/24 --start 1 --end 1024"
            )

    if start_port < 0 or end_port > 65535 or start_port > end_port:
        raise SystemExit("Invalid port range. Use 0-65535 and start <= end.")

    start = time.time()
    network_scan(cidr, start_port, end_port, timeout, threads, ping_port)
    end = time.time()

    print(f"\nScan finished in {round(end - start, 2)}s")
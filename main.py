import socket
import threading
import ipaddress
import queue
import time

TIMEOUT = 0.5
THREADS = 200

print_lock = threading.Lock()
task_queue = queue.Queue()

def tcp_ping(ip, port=80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

def scan_port(ip, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            results.append(port)
    except:
        pass

def port_worker(ip, ports, results):
    while not ports.empty():
        port = ports.get()
        scan_port(ip, port, results)
        ports.task_done()

def scan_ports(ip, start_port, end_port):
    ports = queue.Queue()
    for p in range(start_port, end_port + 1):
        ports.put(p)

    results = []
    threads = []

    for _ in range(min(THREADS, ports.qsize())):
        t = threading.Thread(target=port_worker, args=(ip, ports, results))
        t.daemon = True
        t.start()
        threads.append(t)

    ports.join()
    return sorted(results)

def network_worker(start_port, end_port):
    while not task_queue.empty():
        ip = task_queue.get()
        if tcp_ping(ip):
            with print_lock:
                print(f"[+] Host up: {ip}")
            open_ports = scan_ports(ip, start_port, end_port)
            if open_ports:
                with print_lock:
                    print(f"    Open ports on {ip}: {open_ports}")
            else:
                with print_lock:
                    print(f"    No open ports found on {ip}")
        task_queue.task_done()

def network_scan(cidr, start_port, end_port):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print("Invalid CIDR")
        return

    for ip in net.hosts():
        task_queue.put(str(ip))

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=network_worker, args=(start_port, end_port))
        t.daemon = True
        t.start()
        threads.append(t)

    task_queue.join()

if __name__ == "__main__":
    print("=== Network + Port Scanner ===\n")

    cidr = input("Target network (CIDR, e.g. 192.168.1.0/24): ").strip()
    start_port = int(input("Start port: "))
    end_port = int(input("End port: "))

    start = time.time()
    network_scan(cidr, start_port, end_port)
    end = time.time()

    print(f"\nScan finished in {round(end - start, 2)}s")
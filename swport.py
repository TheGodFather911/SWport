import socket
import threading
import ipaddress
import time
import argparse
import subprocess
from datetime import datetime
from queue import Queue

# swport - Advanced Port Scanner made by Samurai_vxtW

class EmiliPortScanner:
    def __init__(self, target, port_range=(1, 1024), timeout=3.0, max_threads=50, show_only_open=False, udp=False, os_detect=False):
        self.target = target
        self.port_range = port_range
        self.timeout = timeout
        self.max_threads = max_threads
        self.show_only_open = show_only_open
        self.udp = udp
        self.os_detect = os_detect
        self.open_ports = []
        self.filtered_ports = []
        self.closed_ports = []
        self.lock = threading.Lock()
        self.port_queue = Queue()
        self.target_ip = self.resolve_target(target)
        self.latency = None
        self.ttl_guess = None

    def resolve_target(self, target):
        try:
            start_time = time.time()
            ip = socket.gethostbyname(target)
            end_time = time.time()
            self.latency = round((end_time - start_time), 2)
            print(f"swport scan report for {target} ({ip})")
            print(f"Host is up ({self.latency}s latency).")
            print(f"Other addresses for {target} (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f")
            return ip
        except socket.gaierror:
            print("[ERROR] Unable to resolve target.")
            return None

    def scan(self):
        if not self.target_ip:
            print("[ERROR] Invalid target. Scan aborted.")
            return

        for port in range(self.port_range[0], self.port_range[1] + 1):
            self.port_queue.put(port)

        threads = []
        for _ in range(min(self.max_threads, self.port_queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if self.os_detect:
            self.perform_os_detection()

        total_ports = (self.port_range[1] - self.port_range[0]) + 1
        closed_count = len(self.closed_ports)
        print(f"Not shown: {closed_count} closed tcp ports (reset)")

        print("PORT      STATE    SERVICE")
        for port, service in sorted(self.open_ports):
            print(f"{str(port) + '/tcp':<10} open     {service}")
        for port in sorted(self.filtered_ports):
            print(f"{str(port) + '/tcp':<10} filtered Unknown")

    def perform_os_detection(self):
        print("\n[INFO] Performing ICMP OS detection (ping-based)...")
        try:
            ping_cmd = ["ping", "-c", "1", self.target_ip]
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "ttl=" in line:
                        ttl_value = int(line.split("ttl=")[1].split()[0])
                        if ttl_value <= 64:
                            os_family = "Linux/Unix"
                        elif ttl_value <= 128:
                            os_family = "Windows"
                        elif ttl_value <= 255:
                            os_family = "Cisco/Networking OS"
                        else:
                            os_family = "Unknown"

                        print(f"OS Guess: TTL {ttl_value} → Likely OS: {os_family}")
                        return
            print("[OS DETECTED] Could not determine TTL from ping output.")
        except Exception as e:
            print(f"[OS DETECTION ERROR] Could not run ping: {e}")

    def worker(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            if self.udp:
                self.scan_udp_port(port)
            else:
                self.scan_single_port(port)
            self.port_queue.task_done()

    def scan_single_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                with self.lock:
                    if result == 0:
                        service = self.resolve_service(port)
                        self.open_ports.append((port, service))
                    elif result == 111:
                        self.closed_ports.append(port)
                    else:
                        self.filtered_ports.append(port)
        except socket.error:
            pass

    def scan_udp_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(b"\x00", (self.target_ip, port))
                try:
                    sock.recvfrom(1024)
                    with self.lock:
                        self.open_ports.append((port, "udp"))
                except socket.timeout:
                    with self.lock:
                        self.filtered_ports.append(port)
        except socket.error:
            pass

    @staticmethod
    def resolve_service(port):
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Unknown"


def parse_port_range(port_input):
    try:
        start, end = map(int, port_input.split('-'))
        return start, end
    except ValueError:
        print("[ERROR] Invalid port range format. Use START-END.")
        return None


def main():
    parser = argparse.ArgumentParser(description="swport - Port Scanner by Samurai_vxtW")
    parser.add_argument("target", help="Target IP or domain to scan")
    parser.add_argument("-p", "--ports", default="20-100", help="Port range to scan (e.g. 20-80)")
    parser.add_argument("--open", action="store_true", help="Only show open ports")
    parser.add_argument("--udp", "-sU", action="store_true", help="Enable UDP scan")
    parser.add_argument("--os", "-Os", action="store_true", help="Enable OS detection")

    args = parser.parse_args()
    port_range = parse_port_range(args.ports)
    if not port_range:
        return

    scanner = EmiliPortScanner(
        args.target,
        port_range,
        show_only_open=args.open,
        udp=args.udp,
        os_detect=args.os
    )
    scanner.scan()


if __name__ == '__main__':
    main()

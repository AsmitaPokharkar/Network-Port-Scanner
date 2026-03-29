import socket
import threading
import time
import queue

COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
    445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8080: 'HTTP-Alt', 1433: 'MSSQL', 27017: 'MongoDB',
}

class PortScanner:
    def __init__(self, target, start_port, end_port, protocol='tcp',
                 timeout=0.5, max_workers=500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.protocol = protocol.lower()
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()
        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []            
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_tcp_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service, 'tcp'))
                self.result_queue.put(('open', port, service, 'tcp'))
            s.close()
        except Exception as e:
            self.result_queue.put(('error', port, str(e), 'tcp'))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def _scan_udp_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(b'', (self.target, port))
            try:
                data, addr = s.recvfrom(1024)
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service, 'udp'))
                self.result_queue.put(('open', port, service, 'udp'))
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                pass
            except Exception as e:
                self.result_queue.put(('error', port, str(e), 'udp'))
            finally:
                s.close()
        except Exception as e:
            self.result_queue.put(('error', port, str(e), 'udp'))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        if self.protocol == 'tcp':
            self._scan_tcp_port(port)
        else:
            self._scan_udp_port(port)

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()
    def run_scanner_cli(target, start_port, end_port, protocol='tcp', timeout=0.5, max_workers=500):
    scanner = PortScanner(target, start_port, end_port, protocol, timeout, max_workers)

    try:
        resolved_ip = scanner.resolve_target()
        print(f"Target: {target} ({resolved_ip})")
        print(f"Scanning ports {start_port}-{end_port} using {protocol.upper()} protocol...")
    except Exception as e:
        print(f"Error resolving target '{target}': {e}")
        return

    open_ports_found = []
    scan_start_time = time.time()

    def process_results():
        nonlocal open_ports_found
        while True:
            try:
                msg_type, a, b, c = scanner.result_queue.get(timeout=0.1)
                if msg_type == 'open':
                    port, service, proto = a, b, c
                    open_ports_found.append((port, service, proto))
                    print(f"[+] {proto.upper()} Port {port} ({service}) is OPEN")
                elif msg_type == 'error':
                    port, error_msg, proto = a, b, c
                    print(f"[!] Error on {proto.upper()} port {port}: {error_msg}")
                elif msg_type == 'progress':
                    scanned, total = a, b
                    if total > 0:
                        progress_percent = (scanned / total) * 100
                        if scanned % (total // 10 or 1) == 0 or scanned == total:
                            print(f"\rScanning: {scanned}/{total} ({progress_percent:.1f}%) -- Elapsed: {time.time() - scan_start_time:.2f}s", end='')
                elif msg_type == 'done':
                    break
            except queue.Empty:
                if not scanner_thread.is_alive():
                    break
            except Exception as e:
                print(f"Error processing result: {e}")
                break

    scanner_thread = threading.Thread(target=scanner.run, daemon=True)
    result_processor_thread = threading.Thread(target=process_results, daemon=True)

    scanner_thread.start()
    result_processor_thread.start()

    scanner_thread.join() 
    result_processor_thread.join() 

    print("\nScan complete.")
    if open_ports_found:
        print("\n--- Open Ports Summary ---")
        for port, service, proto in sorted(open_ports_found, key=lambda x: x[0]):
            print(f"{proto.upper()} Port {port} ({service})")
    else:
        print("No open ports found.")
    print(f"Total scan time: {time.time() - scan_start_time:.2f}s")

print("\n--- Running TCP Scan on localhost (Ports 1-1024) ---")
run_scanner_cli(target='localhost', start_port=1, end_port=1024, protocol='tcp', timeout=0.1, max_workers=200)

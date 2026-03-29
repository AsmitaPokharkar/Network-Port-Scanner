#!/usr/bin/env python3
"""
Enhanced Network Port Scanner GUI
- TCP and UDP scanning
- Adjustable timeout and thread count
- CSV export
- Extended service map
- Real-time status log
"""

import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Service Map (extended)
COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
    445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8080: 'HTTP-Alt', 1433: 'MSSQL', 27017: 'MongoDB',
}

# Scanner Worker
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
        # UDP scan: send empty packet and check for ICMP unreachable via timeout
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            # Send empty datagram
            s.sendto(b'', (self.target, port))
            # Wait for response (ICMP unreachable or any data)
            try:
                data, addr = s.recvfrom(1024)
                # If we receive any data, port might be open
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service, 'udp'))
                self.result_queue.put(('open', port, service, 'udp'))
            except socket.timeout:
                # No response – port may be open or filtered
                pass
            except ConnectionRefusedError:
                # ICMP port unreachable: port closed
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

# Tkinter GUI 
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Enhanced Network Port Scanner")
        self.geometry("800x600")
        self.minsize(750, 550)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 100

        self._build_ui()

    def _build_ui(self):
        # --- Notebook (tabbed interface) o
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # ----- Settings Frame -----
        settings_frame = ttk.LabelFrame(main_frame, text="Scan Settings")
        settings_frame.pack(fill="x", pady=(0,10))

        # Row 0: Target
        ttk.Label(settings_frame, text="Target (IP / Hostname):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.ent_target = ttk.Entry(settings_frame, width=30)
        self.ent_target.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(settings_frame, text="Start Port:").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.ent_start = ttk.Entry(settings_frame, width=8)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(settings_frame, text="End Port:").grid(row=0, column=4, padx=5, pady=5, sticky="e")
        self.ent_end = ttk.Entry(settings_frame, width=8)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=5, pady=5, sticky="w")

        # Row 1: Advanced options
        ttk.Label(settings_frame, text="Timeout (s):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.ent_timeout = ttk.Entry(settings_frame, width=8)
        self.ent_timeout.insert(0, "0.5")
        self.ent_timeout.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(settings_frame, text="Max Threads:").grid(row=1, column=2, padx=5, pady=5, sticky="e")
        self.ent_threads = ttk.Entry(settings_frame, width=8)
        self.ent_threads.insert(0, "500")
        self.ent_threads.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(settings_frame, text="Protocol:").grid(row=1, column=4, padx=5, pady=5, sticky="e")
        self.protocol_var = tk.StringVar(value="tcp")
        self.cb_protocol = ttk.Combobox(settings_frame, textvariable=self.protocol_var,
                                         values=["tcp", "udp"], state="readonly", width=8)
        self.cb_protocol.grid(row=1, column=5, padx=5, pady=5, sticky="w")

        # Row 2: Buttons
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.grid(row=2, column=0, columnspan=6, pady=10)
        self.btn_start = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.btn_start.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        self.btn_clear = ttk.Button(btn_frame, text="Clear Results", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=5)
        self.btn_save = ttk.Button(btn_frame, text="Save Results", command=self.save_results, state="disabled")
        self.btn_save.pack(side="left", padx=5)

        # ----- Progress and Status -----
        progress_frame = ttk.LabelFrame(main_frame, text="Progress")
        progress_frame.pack(fill="x", pady=(0,10))

        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(5,0))

        status_frame = ttk.Frame(progress_frame)
        status_frame.pack(fill="x", pady=5)
        self.var_status = tk.StringVar(value="Idle")
        ttk.Label(status_frame, textvariable=self.var_status).pack(side="left", padx=10)
        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        ttk.Label(status_frame, textvariable=self.var_elapsed).pack(side="right", padx=10)

        # ----- Output Area (split into Log and Results) -----
        output_frame = ttk.LabelFrame(main_frame, text="Output")
        output_frame.pack(fill="both", expand=True)

        # Left side: Log (text widget)
        log_frame = ttk.LabelFrame(output_frame, text="Log")
        log_frame.pack(side="left", fill="both", expand=True, padx=(0,5), pady=5)
        self.txt_log = tk.Text(log_frame, height=12, wrap="word", state="normal")
        self.txt_log.pack(side="left", fill="both", expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt_log.yview)
        log_scroll.pack(side="right", fill="y")
        self.txt_log.configure(yscrollcommand=log_scroll.set)

        # Right side: Results (treeview for open ports)
        results_frame = ttk.LabelFrame(output_frame, text="Open Ports")
        results_frame.pack(side="right", fill="both", expand=True, padx=(5,0), pady=5)
        self.tree = ttk.Treeview(results_frame, columns=("port", "service", "protocol"), show="headings")
        self.tree.heading("port", text="Port")
        self.tree.heading("service", text="Service")
        self.tree.heading("protocol", text="Protocol")
        self.tree.column("port", width=80, anchor="center")
        self.tree.column("service", width=150, anchor="w")
        self.tree.column("protocol", width=80, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)

    # Control Handlers
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port = int(self.ent_end.get().strip())
            timeout = float(self.ent_timeout.get().strip())
            max_threads = int(self.ent_threads.get().strip())
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid number: {e}")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range must be within 0–65535 and start ≤ end.")
            return

        if timeout <= 0:
            messagebox.showerror("Input Error", "Timeout must be positive.")
            return
        if max_threads < 1:
            messagebox.showerror("Input Error", "Thread count must be at least 1.")
            return

        protocol = self.protocol_var.get().lower()
        if protocol not in ('tcp', 'udp'):
            messagebox.showerror("Input Error", "Protocol must be TCP or UDP.")
            return

        self.scanner = PortScanner(target, start_port, end_port, protocol,
                                   timeout=timeout, max_workers=max_threads)

        # Pre-resolve target
        try:
            resolved_ip = self.scanner.resolve_target()
            self.log_message(f"Target: {target} ({resolved_ip})")
            self.log_message(f"Range: {start_port}-{end_port} ({protocol.upper()})")
            self.log_message(f"Timeout: {timeout}s, Max threads: {max_threads}")
            self.log_message("Scan started...")
        except Exception as e:
            messagebox.showerror("Resolution Error", f"Failed to resolve target '{target}'.\n{e}")
            self.scanner = None
            return

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self.clear_results(keep_log=False)   # keep log, clear tree and progress
        self.start_time = time.time()
        self.var_status.set("Scanning...")
        self.update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.log_message("Stopping scan...")
            self.var_status.set("Stopping...")

    def clear_results(self, keep_log=True):
        # Clear tree view
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Clear progress bar
        self.progress.configure(value=0, maximum=1)
        # Optionally clear log
        if not keep_log:
            self.txt_log.delete("1.0", tk.END)
        self.var_status.set("Idle")
        self.var_elapsed.set("Elapsed: 0.00s")
        self.btn_save.configure(state="disabled")

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save Results", "No open ports to save.")
            return

        # Ask for file type
        filetype = messagebox.askyesno("Save As", "Save as CSV? (Yes for CSV, No for TXT)")
        default_ext = ".csv" if filetype else ".txt"
        file_path = filedialog.asksaveasfilename(
            title="Save results",
            defaultextension=default_ext,
            initialfile=f"scan_results_{int(time.time())}{default_ext}",
            filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            if file_path.endswith(".csv"):
                import csv
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Service", "Protocol"])
                    for port, service, proto in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                        writer.writerow([port, service, proto])
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Open Ports:\n")
                    for port, service, proto in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                        f.write(f"{proto.upper()} Port {port} ({service}) is open\n")
            messagebox.showinfo("Saved", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file.\n{e}")

    def log_message(self, msg):
        self.txt_log.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {msg}\n")
        self.txt_log.see(tk.END)

    def update_elapsed(self):
        if self.start_time and self.var_status.get() in ("Scanning...", "Stopping..."):
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(200, self.update_elapsed)

    def poll_results(self):
        if not self.scanner:
            return

        try:
            while True:
                msg_type, a, b, c = self.scanner.result_queue.get_nowait()
                if msg_type == 'open':
                    port, service, proto = a, b, c
                    self.tree.insert("", tk.END, values=(port, service, proto))
                elif msg_type == 'error':
                    port, error_msg, proto = a, b, c
                    self.log_message(f"Error on {proto.upper()} port {port}: {error_msg}")
                elif msg_type == 'progress':
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    self.var_status.set(f"Scanning... {scanned}/{total}")
                elif msg_type == 'done':
                    total_open = len(self.scanner.open_ports)
                    self.log_message(f"Scan complete. Open ports found: {total_open}")
                    self.var_status.set("Completed")
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.btn_save.configure(state="normal" if total_open else "disabled")
                    self.start_time = None
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        else:
            if self.var_status.get() in ("Scanning...", "Stopping..."):
                self.var_status.set("Completed")
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            if self.scanner and self.scanner.open_ports:
                self.btn_save.configure(state="normal")


def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()

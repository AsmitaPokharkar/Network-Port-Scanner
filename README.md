# Network-Port-Scanner

# Enhanced Network Port Scanner GUI

A powerful, multi‑threaded TCP/UDP port scanner with a graphical user interface built with Python and Tkinter. This is an enhanced version of the original `nmap_portscan_gui` project, adding UDP scanning, configurable parameters, CSV export, and a split output view.

## Features

- **TCP & UDP scanning** – choose between TCP connect scans or UDP probes
- **Adjustable performance** – set timeout and maximum concurrent threads
- **Extended service identification** – recognizes 20+ common ports (FTP, SSH, HTTP, MySQL, NetBIOS, SMB, etc.)
- **Real‑time progress** – progress bar, elapsed time, and live scan log
- **Live results table** – open ports displayed in a sortable tree view (port, service, protocol)
- **Stop any time** – gracefully cancel a running scan
- **Save results** – export to plain text or CSV format
- **Cross‑platform** – runs on Windows, macOS, and Linux (requires Python 3.7+)

## Requirements

- Python 3.7 or newer
- Tkinter (included in standard Python distribution; on Debian/Ubuntu install `python3-tk`)

No third‑party packages are required.

## Installation

```bash
git clone https://github.com/techtrainer20/nmap_portscan_gui.git
cd nmap_portscan_gui

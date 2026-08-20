# Network Sniffer

A lightweight network traffic sniffer implemented in Python. It captures live IP traffic using raw sockets and parses packet headers at the byte level, with two ways to inspect the results: a command-line stream (`packet_sniffer.py`) and a live web dashboard (`dash_app.py`).

## Abstract

This project demonstrates how packet capture and protocol parsing can be implemented from first principles, without relying on higher-level packet libraries. Traffic is captured directly from a raw socket, and IPv4, TCP, and UDP headers are unpacked manually using Python's `struct` module. The dashboard variant extends this into a live, browser-based view of captured traffic, showing protocol distribution and recent packet details in real time.

## Features

- Live capture of IP traffic using a raw socket in promiscuous mode
- Manual, byte-level parsing of:
  - IPv4 headers (version, header length, TTL, protocol, source/destination IP)
  - TCP headers (source/destination ports, sequence/acknowledgment numbers, URG/ACK/PSH/RST/SYN/FIN flags)
  - UDP headers (source/destination ports, segment size)
- Two interfaces to the same capture logic:
  - `packet_sniffer.py` -- prints parsed packet details to the console as they are captured
  - `dash_app.py` -- runs a Dash/Plotly web dashboard with:
    - a live bar chart of packet counts per protocol (TCP/UDP/IGMP/Other)
    - a live pie chart of protocol distribution
    - a rolling table of the most recently captured packets
    - auto-refresh via a Dash `Interval` component

## Project Layout

- `packet_sniffer.py`: raw-socket capture loop with console output
- `dash_app.py`: raw-socket capture loop running on a background thread, feeding a Dash web UI

## Requirements

- Python 3
- `dash` and `plotly` (for the dashboard variant)

```bash
pip install dash plotly
```

Raw sockets require elevated/administrator privileges and are used here in a Windows-oriented mode (`SIO_RCVALL` / `RCVALL_ON`) to capture all IP traffic on the host's primary interface.

## Usage

Console sniffer:

```bash
python packet_sniffer.py
```

Live dashboard (open the printed local URL in a browser, e.g. `http://127.0.0.1:8050`):

```bash
python dash_app.py
```

Run either script with administrator/elevated privileges so the raw socket can be opened and set to receive all traffic.

## Notes

- This is a learning/demo project focused on manual protocol parsing rather than production packet capture; it does not currently persist captured data or filter traffic beyond basic protocol identification.
- The dashboard keeps only the last 100 packets in memory for the table view.

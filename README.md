# Network Packet Monitor

![rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)

A network packet monitoring tool written in Rust. This tool listens to a specific network interface and monitors incoming and outgoing IPv4 packets, displaying the timestamp, IP addresses, and the resolved domain names for each packet.

**This project was developed in just a few hours as part of a training exercise over the weekend.**

## Features

- Monitors network traffic on a specified interface.
- Displays the timestamp for each packet received or sent.
- Resolves IP addresses to domain names (using reverse DNS lookup).
- Filters out local IP addresses and only shows external ones.

## Requirements

- Rust 1.50+ installed on your system.
- `trust-dns-resolver` crate for DNS resolution.
- `pnet` crate for working with packets.

## Installation

To get started with the project:

1. Clone this repository to your local machine.
   ```bash
   git clone https://github.com/Matheus-git/network-packet-monitor.git
   ```
2. Navigate to the project directory:
   ```bash
    cd network-packet-monitor
   ```
3. Run the program with:
   ```bash
    cargo run
   ```

## 📝 License

This project is open-source under the MIT License.

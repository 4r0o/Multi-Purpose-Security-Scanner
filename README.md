# Multi-Purpose Security Scanner

A class-based command-line tool for common network and website reconnaissance tasks.

## Setup

```bash
python3 -m pip install -r requirements.txt
```

The Whois option requires the `whois` system command:

```bash
sudo apt-get install whois
```

## Usage

```bash
python3 scanner.py
python3 scanner.py --target example.com
```

Choose an operation from the numbered menu. The scanner supports port scanning, IP geolocation, DNS records, website headers, SSL certificate validation, and Whois lookups. Use only against systems you own or are authorized to assess.
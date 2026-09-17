import argparse
import ipaddress
import re
import socket
import ssl
import subprocess
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import requests


class SecurityScanner:
    COMMON_PORTS = (21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8080)
    DNS_RECORDS = ("A", "AAAA", "MX", "NS", "TXT")

    def __init__(self, target=None):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Multi-Purpose-Security-Scanner/1.0"})

    def banner(self):
        print(r"""
 __  __       _ _   _       ____
|  \/  |_   _| | |_(_)     / ___|  ___  ___ _   _ _ __ ___
| |\/| | | | | | __| |_____\___ \ / _ \/ __| | | | '__/ _ \
| |  | | |_| | | |_| |_____|___) |  __/ (__| |_| | | |  __/
|_|  |_|\__,_|_|\__|_|     |____/ \___|\___|\__,_|_|  \___|
""")
        print("Multi-Purpose Security Scanner\n")

    def menu(self):
        print("1. Port Scanner")
        print("2. IP Information")
        print("3. DNS Lookup")
        print("4. Website Headers")
        print("5. SSL Checker")
        print("6. Whois Lookup")
        print("0. Exit")
        return input("Select an option: ").strip()

    def run(self):
        self.banner()
        while True:
            choice = self.menu()
            if choice == "0":
                print("Exiting.")
                return
            if choice not in {str(number) for number in range(1, 7)}:
                print("Invalid option. Choose a number from 0 to 6.\n")
                continue
            target = self.get_target()
            if target is None:
                print()
                continue
            try:
                result = {
                    "1": self.port_scanner,
                    "2": self.ip_information,
                    "3": self.dns_lookup,
                    "4": self.website_headers,
                    "5": self.ssl_checker,
                    "6": self.whois_lookup,
                }[choice](target)
                self.print_result(result)
            except (OSError, requests.RequestException, socket.gaierror, ValueError) as error:
                print(f"Error: {error}")
            except Exception as error:
                print(f"Unexpected error: {error}")
            print()

    def get_target(self):
        target = self.target or input("Enter a host, IP address, or domain: ").strip()
        target = self.normalize_target(target)
        if not target:
            print("A valid target is required.")
            return None
        return target

    @staticmethod
    def normalize_target(target):
        target = target.strip()
        if not target:
            return None
        parsed = urlparse(target if "://" in target else f"//{target}")
        hostname = parsed.hostname
        if not hostname or len(hostname) > 253:
            return None
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", hostname):
                return None
        return hostname

    def port_scanner(self, target):
        results = {"target": target, "open_ports": [], "closed_ports": []}
        for port in self.COMMON_PORTS:
            try:
                with socket.create_connection((target, port), timeout=1):
                    results["open_ports"].append(port)
            except (socket.timeout, ConnectionRefusedError, OSError):
                results["closed_ports"].append(port)
        return results

    def ip_information(self, target):
        address = socket.gethostbyname(target)
        response = self.session.get(f"http://ip-api.com/json/{address}", timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            raise ValueError(data.get("message", "IP lookup failed"))
        return data

    def dns_lookup(self, target):
        results = {record_type: [] for record_type in self.DNS_RECORDS}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        for record_type in self.DNS_RECORDS:
            try:
                answers = resolver.resolve(target, record_type)
                results[record_type] = [answer.to_text() for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                results[record_type] = []
        return results

    def website_headers(self, target):
        response = self.session.get(f"https://{target}", timeout=10, allow_redirects=True)
        return {
            "requested_url": response.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Not disclosed"),
            "headers": dict(response.headers),
        }

    def ssl_checker(self, target):
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=target) as secure_socket:
                certificate = secure_socket.getpeercert()
                cipher = secure_socket.cipher()
                protocol = secure_socket.version()
        not_before = self.parse_certificate_date(certificate.get("notBefore"))
        not_after = self.parse_certificate_date(certificate.get("notAfter"))
        return {
            "subject": dict(item[0] for item in certificate.get("subject", ())),
            "issuer": dict(item[0] for item in certificate.get("issuer", ())),
            "valid_from": not_before.isoformat() if not_before else "Unknown",
            "valid_until": not_after.isoformat() if not_after else "Unknown",
            "is_valid_now": bool(not_before and not_after and not_before <= datetime.utcnow() <= not_after),
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "Unknown",
        }

    @staticmethod
    def parse_certificate_date(value):
        if not value:
            return None
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")

    def whois_lookup(self, target):
        completed = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0 and not completed.stdout.strip():
            raise RuntimeError(completed.stderr.strip() or "Whois lookup failed")
        return completed.stdout.strip()

    @staticmethod
    def print_result(result):
        if isinstance(result, str):
            print(result or "No result returned.")
            return
        if "headers" in result:
            print(f"URL: {result['requested_url']}")
            print(f"Status: {result['status_code']}")
            print(f"Server: {result['server']}")
            for key, value in result["headers"].items():
                print(f"{key}: {value}")
            return
        for key, value in result.items():
            label = key.replace("_", " ").title()
            if isinstance(value, list):
                value = ", ".join(map(str, value)) or "None"
            print(f"{label}: {value}")


def main():
    parser = argparse.ArgumentParser(description="Multi-purpose security scanner")
    parser.add_argument("--target", help="Default host, IP address, or domain")
    args = parser.parse_args()
    SecurityScanner(args.target).run()


if __name__ == "__main__":
    main()
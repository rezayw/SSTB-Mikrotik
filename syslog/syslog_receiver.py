"""
SSTB Syslog Receiver
Listens on UDP 514 for MikroTik firewall logs and forwards to backend.
"""

import socket
import re
import httpx
import logging
import os
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SYSLOG] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
SYSLOG_PORT = 514
BUFFER_SIZE = 4096

# Regex patterns to extract attack info from MikroTik logs
PATTERNS = {
    "ssh_brute": re.compile(
        r"firewall.*forward.*src-address=([\d.]+).*dst-port=22", re.IGNORECASE
    ),
    "winbox": re.compile(
        r"firewall.*forward.*src-address=([\d.]+).*dst-port=8291", re.IGNORECASE
    ),
    "port_scan": re.compile(
        r"firewall.*input.*src-address=([\d.]+).*in:.*port-scan", re.IGNORECASE
    ),
    "generic_drop": re.compile(
        r"firewall.*(?:dropped|denied|blocked).*src-address=([\d.]+).*dst-port=(\d+)",
        re.IGNORECASE,
    ),
    "src_address": re.compile(r"src-address=([\d.]+)", re.IGNORECASE),
    "dst_port": re.compile(r"dst-port=(\d+)", re.IGNORECASE),
    "protocol": re.compile(r"proto=(tcp|udp|icmp)", re.IGNORECASE),
}

# Wait for backend to be ready
def wait_for_backend(max_retries: int = 30):
    for i in range(max_retries):
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{BACKEND_URL}/health")
                if resp.status_code == 200:
                    logger.info(f"Backend is ready at {BACKEND_URL}")
                    return True
        except Exception:
            pass
        logger.info(f"Waiting for backend... ({i+1}/{max_retries})")
        time.sleep(5)
    return False


def parse_mikrotik_log(message: str) -> dict | None:
    """Parse MikroTik syslog message to extract threat info."""
    # Try to extract source IP
    src_match = PATTERNS["src_address"].search(message)
    if not src_match:
        return None

    source_ip = src_match.group(1)

    # Skip private IPs
    if (
        source_ip.startswith("192.168.")
        or source_ip.startswith("10.")
        or source_ip.startswith("172.")
        or source_ip == "127.0.0.1"
    ):
        return None

    # Extract port
    port_match = PATTERNS["dst_port"].search(message)
    target_port = int(port_match.group(1)) if port_match else None

    # Extract protocol
    proto_match = PATTERNS["protocol"].search(message)
    protocol = proto_match.group(1).lower() if proto_match else "tcp"

    # Determine attack type
    attack_type = "unknown"
    if target_port == 22:
        attack_type = "ssh_brute"
    elif target_port == 8291:
        attack_type = "winbox_scan"
    elif target_port == 23:
        attack_type = "telnet_brute"
    elif target_port in (80, 443, 8080, 8443):
        attack_type = "http_probe"
    elif target_port in (3389, 5900):
        attack_type = "rdp_scan"
    elif "port-scan" in message.lower():
        attack_type = "port_scan"
    elif "brute" in message.lower():
        attack_type = "brute_force"

    return {
        "source_ip": source_ip,
        "target_port": target_port,
        "protocol": protocol,
        "attack_type": attack_type,
        "raw_log": message[:1000],  # Truncate
    }


def forward_to_backend(event: dict):
    """Send parsed event to backend API."""
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(f"{BACKEND_URL}/threats/ingest", json=event)
            if resp.status_code == 200:
                logger.info(
                    f"Forwarded threat: {event['source_ip']} "
                    f"port={event.get('target_port')} "
                    f"type={event.get('attack_type')}"
                )
            else:
                logger.warning(f"Backend returned {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.error(f"Failed to forward to backend: {e}")


def main():
    logger.info("SSTB Syslog Receiver starting...")

    if not wait_for_backend():
        logger.error("Backend not reachable, exiting.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SYSLOG_PORT))
    logger.info(f"Listening on UDP port {SYSLOG_PORT}...")

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = data.decode("utf-8", errors="replace").strip()
            logger.debug(f"Received from {addr[0]}: {message[:200]}")

            event = parse_mikrotik_log(message)
            if event:
                forward_to_backend(event)
        except KeyboardInterrupt:
            logger.info("Shutting down syslog receiver.")
            break
        except Exception as e:
            logger.error(f"Error processing message: {e}")


if __name__ == "__main__":
    main()

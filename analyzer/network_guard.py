import ipaddress
import socket
from urllib.parse import urlparse, urlunparse


ALLOWED_PORTS = {80, 443}


def _validate_public_host(hostname: str, port: int):
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost targets are blocked for safety.")

    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The hostname could not be resolved.")

    addresses = {info[4][0] for info in infos}

    if not addresses:
        raise ValueError("The hostname did not resolve to a usable address.")

    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                "Private, local, reserved, or internal-network targets are blocked."
            )


def normalize_and_validate_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("Please enter a website URL.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    if port not in ALLOWED_PORTS:
        raise ValueError("For safety, WebShield only scans standard web ports 80 and 443.")

    _validate_public_host(parsed.hostname, port)

    # Remove fragments because they are browser-side only.
    cleaned = parsed._replace(fragment="")
    return urlunparse(cleaned)

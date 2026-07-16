#!/usr/bin/env python3
"""
Standalone QR Code Generator for Mobile Companion Setup

Generates QR code for backend URL discovery.
Can be imported by main.py or run standalone.
"""

import qrcode
import socket
from io import BytesIO
from typing import Optional


def get_local_ip() -> str:
    """Get the outbound LAN IP by connecting a UDP socket (no packet sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception:
            return "127.0.0.1"


def generate_qr_bytes(base_url: str, ws_url: str, api_key: Optional[str] = None) -> bytes:
    """Generate QR code as PNG bytes"""

    # Build setup URL
    setup_url = f"oneinfinity://setup?base={base_url}&ws={ws_url}"
    if api_key:
        setup_url += f"&key={api_key}"

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(setup_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to PNG bytes
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    return buf.read()


def generate_qr_for_port(port: int = 47291, api_key: Optional[str] = None) -> bytes:
    """Generate QR code for backend on given port"""
    local_ip = get_local_ip()
    base_url = f"http://{local_ip}:{port}"
    ws_url = f"ws://{local_ip}:{port}"

    return generate_qr_bytes(base_url, ws_url, api_key)


if __name__ == "__main__":
    # Standalone mode - save QR to file
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 47291
    output_file = sys.argv[2] if len(sys.argv) > 2 else "setup_qr.png"
    custom_ip = sys.argv[3] if len(sys.argv) > 3 else None

    if custom_ip:
        # Use provided IP
        qr_bytes = generate_qr_bytes(f"http://{custom_ip}:{port}", f"ws://{custom_ip}:{port}")
        local_ip = custom_ip
    else:
        qr_bytes = generate_qr_for_port(port)
        local_ip = get_local_ip()

    with open(output_file, 'wb') as f:
        f.write(qr_bytes)

    print(f"✅ QR code saved to {output_file}")
    print(f"📱 Backend URL: http://{local_ip}:{port}")
    print(f"🔗 Setup URL: oneinfinity://setup?base=http://{local_ip}:{port}&ws=ws://{local_ip}:{port}")

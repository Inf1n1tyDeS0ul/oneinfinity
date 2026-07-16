"""
mDNS Service Advertising for Mobile Companion Auto-Discovery

Advertises OneInfinity backend on local network so mobile apps can find it automatically.
"""

import socket
from typing import Optional


class MdnsAdvertiser:
    """Advertise OneInfinity backend via mDNS/Bonjour"""

    def __init__(self, port: int = 47291):
        self.port = port
        self.zeroconf = None
        self.service_info = None

    def _get_local_ip(self) -> str:
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

    def start(self):
        """Advertise OneInfinity backend via mDNS"""
        try:
            from zeroconf import ServiceInfo, Zeroconf

            # Get local IP
            local_ip = self._get_local_ip()
            hostname = socket.gethostname()

            if local_ip == "127.0.0.1":
                print("[mDNS] Warning: Could only detect loopback IP. Real devices may not find the backend.")

            # Create service info
            self.service_info = ServiceInfo(
                "_oneinfinity._tcp.local.",
                "OneInfinity Backend._oneinfinity._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties={
                    "version": "1.0",
                    "api": "http",
                    "ws": "websocket",
                    "platform": "oneinfinity"
                },
                server=f"{hostname}.local."
            )

            # Register service
            self.zeroconf = Zeroconf()
            self.zeroconf.register_service(self.service_info)
            print(f"[mDNS] Advertising backend at {local_ip}:{self.port}")

        except ImportError:
            print("[mDNS] zeroconf not installed, skipping mDNS advertising")
            print("[mDNS] Install: pip install zeroconf")
        except Exception as e:
            print(f"[mDNS] Failed to start advertising: {e}")

    def stop(self):
        """Stop advertising"""
        try:
            if self.zeroconf and self.service_info:
                self.zeroconf.unregister_service(self.service_info)
                self.zeroconf.close()
                print("[mDNS] Stopped advertising")
        except Exception as e:
            print(f"[mDNS] Error stopping: {e}")


# Global instance
_mdns_advertiser: Optional[MdnsAdvertiser] = None


def start_mdns_advertising(port: int = 47291):
    """Start mDNS advertising (called from main.py)"""
    global _mdns_advertiser
    _mdns_advertiser = MdnsAdvertiser(port)
    _mdns_advertiser.start()


def stop_mdns_advertising():
    """Stop mDNS advertising"""
    global _mdns_advertiser
    if _mdns_advertiser:
        _mdns_advertiser.stop()

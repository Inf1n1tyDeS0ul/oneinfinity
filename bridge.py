import http.server
import urllib.request
import sys

class BridgeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="web/frontend/dist", **kwargs)

    def do_GET(self):
        # Proxy API to Docker Backend (running on 8001)
        if self.path.startswith('/api'):
            url = f"http://localhost:8001{self.path}"
            try:
                with urllib.request.urlopen(url) as response:
                    self.send_response(response.status)
                    for header, value in response.getheaders():
                        self.send_header(header, value)
                    self.end_headers()
                    self.wfile.write(response.read())
            except Exception as e:
                self.send_error(502, f"Backend unreachable: {e}")
        else:
            # Handle SPA Routing (Redirect clean URLs to index.html)
            if not "." in self.path:
                self.path = "/index.html"
            super().do_GET()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    print(f"Starting Network Bridge on port {port}...")
    print(f"Access via: http://localhost:{port}")
    try:
        http.server.HTTPServer(('0.0.0.0', port), BridgeHandler).serve_forever()
    except PermissionError:
        print(f"ERROR: Port {port} requires sudo/root permissions.")
        print(f"Please run with: sudo PORT={port} python3 bridge.py")

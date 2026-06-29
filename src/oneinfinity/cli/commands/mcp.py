"""
MCP server command handler
"""
import json
import sys
from pathlib import Path


def cmd_mcp_server(args):
    """Handle mcp-server command."""
    # Import here to avoid loading MCP dependencies on every CLI invocation
    try:
        from oneinfinity.mcp import server as mcp_server
    except ImportError as e:
        print(f"  [!] MCP server dependencies not available: {e}", file=sys.stderr)
        print("      Run: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

    if args.manifest:
        # Print tool manifest and exit
        manifest = mcp_server.get_tool_manifest()
        print(json.dumps(manifest, indent=2))
        sys.exit(0)

    if args.serve:
        # Start HTTP server for MCP protocol
        print("  [*] Starting OneInfinity MCP Server...")
        print(f"      Host: {args.host}")
        print(f"      Port: {args.port}")
        print()
        print("  Available tools:")
        manifest = mcp_server.get_tool_manifest()
        for tool in manifest["tools"]:
            print(f"    - {tool['name']}: {tool['description']}")
        print()
        print("  [✓] Server ready for Claude CLI/Gemini CLI/Ollama")
        print()

        # Simple HTTP server implementation
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler

            class MCPHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path == "/manifest":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        manifest = mcp_server.get_tool_manifest()
                        self.wfile.write(json.dumps(manifest).encode())
                    else:
                        self.send_response(404)
                        self.end_headers()

                def do_POST(self):
                    if self.path == "/tool":
                        content_length = int(self.headers['Content-Length'])
                        body = self.rfile.read(content_length)
                        try:
                            request_data = json.loads(body)
                            tool_name = request_data.get("tool")
                            parameters = request_data.get("parameters", {})

                            result = mcp_server.call_tool(tool_name, parameters)

                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(json.dumps(result).encode())
                        except Exception as e:
                            self.send_response(500)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            error_response = {"error": str(e)}
                            self.wfile.write(json.dumps(error_response).encode())
                    else:
                        self.send_response(404)
                        self.end_headers()

                def log_message(self, format, *args):
                    # Suppress default HTTP logging
                    pass

            server = HTTPServer((args.host, args.port), MCPHandler)
            server.serve_forever()

        except KeyboardInterrupt:
            print("\n  [✓] MCP server stopped")
            sys.exit(0)
        except Exception as e:
            print(f"  [!] Server error: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        # No action specified, print help
        print("  Usage:")
        print("    oneinfinity mcp-server --manifest      # Print tool manifest")
        print("    oneinfinity mcp-server --serve         # Start HTTP server")
        print("    oneinfinity mcp-server --serve --port 8080")
        sys.exit(0)

from http.server import BaseHTTPRequestHandler, HTTPServer


HOST = "127.0.0.1"
PORT = 8080


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return "Apache/2.4.29 (Ubuntu)"

    def do_GET(self):
        body = b"Recon Tool local mock\n"

        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), MockHandler)
    print(f"Mock HTTP server listening on {HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMock HTTP server stopped")
    finally:
        server.server_close()

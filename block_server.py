from http.server import BaseHTTPRequestHandler, HTTPServer

class BlockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
        <html>
          <body style="font-family:sans-serif;text-align:center;margin-top:100px;">
            <h1>Access Blocked</h1>
            <p>This domain was classified as malicious.</p>
          </body>
        </html>
        """)

server = HTTPServer(("127.0.0.1", 80), BlockHandler)
print("Block page running on port 80")
server.serve_forever()

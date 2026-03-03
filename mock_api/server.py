import http.server
import socketserver
import json
import os
import re

PORT = 3000
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

class RansomwareLiveHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Set headers
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        # Route: /v2/recentvictims
        if self.path == '/v2/recentvictims':
            with open(os.path.join(DATA_DIR, 'recentvictims.json'), 'r') as f:
                self.wfile.write(f.read().encode())
            return

        # Route: /v2/groups/<group_name>
        group_match = re.match(r'/v2/groups/([^/]+)', self.path)
        if group_match:
            group_name = group_match.group(1).lower()
            group_file = os.path.join(DATA_DIR, 'groups', f'{group_name}.json')
            
            if os.path.exists(group_file):
                with open(group_file, 'r') as f:
                    self.wfile.write(f.read().encode())
            else:
                # Return generic profile if specific file doesn't exist
                self.wfile.write(json.dumps({
                    "name": group_name,
                    "description": f"Standard profile for {group_name}. This is a mock response.",
                    "locations": "Unknown",
                    "profile": ["No detailed intelligence available in mock."]
                }).encode())
            return

        # Default: 404
        self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def log_message(self, format, *args):
        # Silence logs for cleaner demo output
        pass

print(f"[*] Mock Ransomware.live API running at http://localhost:{PORT}")
print(f"    - Recent Victims: http://localhost:{PORT}/v2/recentvictims")
print(f"    - Group Profiles: http://localhost:{PORT}/v2/groups/<name>")

with socketserver.TCPServer(("", PORT), RansomwareLiveHandler) as httpd:
    httpd.serve_forever()

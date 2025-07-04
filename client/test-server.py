#!/usr/bin/env python3

import http.server
import socketserver
import json
import datetime
import os
import sys

class TestServerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Send response status code
        self.send_response(200)
        
        # Send headers
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Create response with timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tunnel Test Server</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    margin: 50px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }}
                .container {{ 
                    background: rgba(255,255,255,0.1); 
                    padding: 40px; 
                    border-radius: 10px; 
                    backdrop-filter: blur(10px);
                }}
                h1 {{ color: #fff; margin-bottom: 20px; }}
                .info {{ 
                    background: rgba(255,255,255,0.2); 
                    padding: 20px; 
                    border-radius: 5px; 
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎉 Hello World! 🎉</h1>
                <h2>Tunnel Test Server</h2>
                <div class="info">
                    <p><strong>✅ Tunnel is working successfully!</strong></p>
                    <p>Time: {timestamp}</p>
                    <p>Server: Python HTTP Server</p>
                    <p>Request Path: {self.path}</p>
                    <p>Client IP: {self.client_address[0]}</p>
                </div>
                <p>🚀 Your rabbit.go system is working perfectly!</p>
                <p>🔗 This response came through your tunnel connection.</p>
            </div>
        </body>
        </html>
        """
        
        # Send the HTML response
        self.wfile.write(html_response.encode('utf-8'))
        
        # Log the request
        print(f"✅ Request served: {self.path} from {self.client_address[0]} at {timestamp}")
    
    def do_POST(self):
        # Handle POST requests for testing
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        response = {
            "message": "Hello World from POST!",
            "timestamp": datetime.datetime.now().isoformat(),
            "received_data": post_data.decode('utf-8', errors='ignore'),
            "path": self.path
        }
        
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))
        print(f"✅ POST request served: {self.path}")
    
    def log_message(self, format, *args):
        # Custom log format
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {format % args}")

def run_server(port=8080):
    """Run the test server on specified port"""
    
    print("🚀 Starting Tunnel Test Server...")
    print("=" * 50)
    print(f"Port: {port}")
    print(f"URL: http://localhost:{port}")
    print("=" * 50)
    
    try:
        with socketserver.TCPServer(("", port), TestServerHandler) as httpd:
            print(f"✅ Server running on port {port}")
            print("📡 Ready to receive tunnel connections!")
            print("🔗 Create tunnel with:")
            print(f"   ../syne-cli/syne-cli tunnel --server YOUR_VPS:9999 --local-port {port} --token mytoken123")
            print("")
            print("🧪 Test commands:")
            print("   curl http://127.0.0.1:<tunnel-port>")
            print("   curl -X POST -d 'test data' http://127.0.0.1:<tunnel-port>/api")
            print("")
            print("Press Ctrl+C to stop...")
            print("=" * 50)
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"❌ Port {port} is already in use")
            print(f"💡 Try a different port: python3 test-server.py {port + 1}")
        else:
            print(f"❌ Error starting server: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    # Allow custom port from command line
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid port number. Using default port 8080.")
            port = 8080
    
    run_server(port) 
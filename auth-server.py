from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import base64
from datetime import datetime, timedelta
import uuid

AUTHFILE = "users.dat"
AUTHFILE_DELIMITER = "🍆"
BLOCKED_NAMES = ["admin"]

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    # Handle GET requests
    def do_GET(self):
        # Send 200 OK response
        self.send_response(200)
        
        # Set headers (Content-Type and Content-Length)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', '0')
        self.end_headers()
        
        # Return a blank response body
        self.wfile.write(b'')


    # Handle POST requests
    def do_POST(self):
        # Check if the request uses 'Transfer-Encoding: chunked'
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            # Read the chunked body
            body = self._read_chunked_body()
            
        else:
            # Handle non-chunked POST request as before
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')

        if "/%20api/auth/authenticate" not in self.requestline:
            return 
        
        username = json.loads(body)['username']
        usertoken = base64.b64encode(username.encode('utf-8')).decode('utf-8')
        password = json.loads(body)['password']

        print(body)
        if self.blocked_name(username) or self.blocker_pass(password):
            return

        authed, userId = self.auth(username, password)
        if not authed:
            return
        
        # Send 200 OK response
        self.send_response(200)
        
        # Set headers (Content-Type and Content-Length)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()

        current_time = datetime.utcnow()
        one_year_later = current_time + timedelta(days=365)
        formatted_time = one_year_later.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0+00:00"


        response = {
                "token": usertoken,
                "username": username,
                "userId": userId,
                "expireTime": formatted_time
            }
        
        # Return a blank response body
        self.wfile.write(json.dumps(response).encode('utf-8'))


    # Helper method to read chunked body
    def _read_chunked_body(self):
        body = b''
        while True:
            # Read the chunk size in hexadecimal
            chunk_size_str = self.rfile.readline().strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                print(f"Invalid chunk size: {chunk_size_str}")
                break

            # If chunk size is 0, it's the end of the request
            if chunk_size == 0:
                self.rfile.readline()  # Consume the trailing CRLF after the chunk
                break

            # Read the actual chunk
            chunk = self.rfile.read(chunk_size)
            body += chunk

            # Consume the trailing CRLF after the chunk
            self.rfile.readline()

        return body.decode('utf-8')
    
    def blocked_name(self, username):
        if AUTHFILE_DELIMITER in username:
            return True
        return username.lower() in BLOCKED_NAMES
    
    def blocker_pass(self, password):
        if AUTHFILE_DELIMITER in password:
            return True
    
    def auth(self, username, password):
        print(f"Authing {username}.")
        with open(AUTHFILE, 'r+', encoding='utf-8') as f:
            
            for line in f.read().splitlines():
                line = line.rstrip()
                usr, pwd, client_id = line.split(AUTHFILE_DELIMITER)
                if usr.lower() == username.lower():
                    pwd = base64.b16decode(pwd).decode('utf-8')
                    return (password == pwd, client_id)
            client_id = str(uuid.uuid4())
            ENCRYPTEDLOL_password = base64.b16encode(password.encode('utf-8')).decode('utf-8')
            f.write(f"{username}{AUTHFILE_DELIMITER}{ENCRYPTEDLOL_password}{AUTHFILE_DELIMITER}{client_id}\n")
        return (True, client_id)
    
def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting http server on port {port}")
    httpd.serve_forever()


if __name__ == "__main__":
    run()

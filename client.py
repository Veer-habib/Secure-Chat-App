import socket
import threading
import json
from crypto import CryptoManager

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.crypto = CryptoManager()
        self.username = input("Enter username: ")
        self.setup_connection()

    def setup_connection(self):
        host = input("Server IP [localhost]: ") or "localhost"
        port = int(input("Port [5555]: ") or 5555)
        
        try:
            self.sock.connect((host, port))
            print("Connected to server!")
            
            # Key exchange
            server_pubkey = RSA.import_key(self.sock.recv(4096))
            self.crypto.recipient_keys['server'] = server_pubkey
            self.sock.send(self.crypto.public_key.export_key())
            
            # Send username
            self.sock.send(self.username.encode())
            
            # Start message threads
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.send_messages()
            
        except Exception as e:
            print(f"Connection failed: {e}")
            self.sock.close()

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                
                msg = json.loads(data.decode())
                if msg.get('to') == self.username:
                    decrypted = self.crypto.decrypt_message(msg['content'])
                    print(f"\n[New Message] {msg['from']}: {decrypted}")
                else:
                    print("\n[System] Unknown message format")
                    
            except Exception as e:
                print(f"\nReceive error: {e}")
                break

    def send_messages(self):
        print("\nType messages as: recipient:message")
        print("Available commands: /list, /exit\n")
        
        while True:
            try:
                text = input("> ")
                
                if text == "/exit":
                    break
                elif text == "/list":
                    print("\n[System] Listing users not implemented yet")
                    continue
                
                if ":" not in text:
                    print("Format: recipient:message")
                    continue
                
                recipient, message = text.split(":", 1)
                encrypted = self.crypto.encrypt_message('server', message)
                
                self.sock.send(json.dumps({
                    'from': self.username,
                    'to': recipient,
                    'content': encrypted
                }).encode())
                
            except Exception as e:
                print(f"Send error: {e}")
                break
        
        self.sock.close()
        print("Disconnected from server")

if __name__ == "__main__":
    print("Secure Chat Client - Terminal Version")
    ChatClient()

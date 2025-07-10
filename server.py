import socket
import threading
import json
from crypto import CryptoManager

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}
        self.crypto = CryptoManager()
        print(f"Server started on {host}:{port}")
        print("Server public key:", self.crypto.public_key.export_key().decode()[:50] + "...")

    def handle_client(self, conn, addr):
        username = None
        try:
            # Key exchange
            conn.send(self.crypto.public_key.export_key())
            client_pubkey = RSA.import_key(conn.recv(4096))
            self.crypto.recipient_keys[addr] = client_pubkey
            
            username = conn.recv(1024).decode()
            self.clients[username] = conn
            print(f"\n[+] {username} connected from {addr}")

            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                try:
                    msg = json.loads(data.decode())
                    recipient = msg['to']
                    if recipient in self.clients:
                        self.clients[recipient].send(data)
                        print(f"Message routed: {username} -> {recipient}")
                except Exception as e:
                    print(f"Error: {e}")

        except Exception as e:
            print(f"Client error: {e}")
        finally:
            if username in self.clients:
                del self.clients[username]
                print(f"[-] {username} disconnected")
            conn.close()

    def start(self):
        while True:
            conn, addr = self.server.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    print("Secure Chat Server - Terminal Version")
    ChatServer().start()

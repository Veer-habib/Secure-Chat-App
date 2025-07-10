from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class CryptoManager:
    def __init__(self):
        self.key_pair = RSA.generate(2048)
        self.public_key = self.key_pair.publickey()
        self.private_key = self.key_pair
        self.recipient_keys = {}

    def encrypt_message(self, recipient, message):
        if recipient not in self.recipient_keys:
            raise ValueError("Recipient not found")
        
        # Hybrid encryption (AES + RSA)
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
        
        # Encrypt AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(self.recipient_keys[recipient])
        enc_aes_key = cipher_rsa.encrypt(aes_key)
        
        return {
            'iv': base64.b64encode(cipher_aes.iv).decode(),
            'ciphertext': base64.b64encode(ct_bytes).decode(),
            'enc_key': base64.b64encode(enc_aes_key).decode()
        }

    def decrypt_message(self, encrypted_msg):
        try:
            iv = base64.b64decode(encrypted_msg['iv'])
            ct = base64.b64decode(encrypted_msg['ciphertext'])
            enc_key = base64.b64decode(encrypted_msg['enc_key'])
            
            # Decrypt AES key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(enc_key)
            
            # Decrypt message
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher_aes.decrypt(ct), AES.block_size)
            return pt.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

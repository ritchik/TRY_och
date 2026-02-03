from typing import Optional
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from werkzeug.security import generate_password_hash


class CryptoService:
    

    @staticmethod
    def encrypt_content(content: str, password: str) -> tuple[str, str]:
       
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        fernet = Fernet(key)
        encrypted_content = fernet.encrypt(content.encode())
        password_hash = generate_password_hash(password)

        return encrypted_content.decode('utf-8'), password_hash

    @staticmethod
    def decrypt_content(encrypted_content: str, password: str) -> Optional[str]:
        
        try:
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            fernet = Fernet(key)
            decrypted_content = fernet.decrypt(encrypted_content.encode()).decode('utf-8')
            return decrypted_content
        except Exception:
            return None

    @staticmethod
    def sign_data(data_to_sign: bytes, private_key_pem: str) -> str:
       
        from flask import current_app
         
        private_key = load_pem_private_key(
            private_key_pem.encode(), 
            password=current_app.config['SECRET_KEY'].encode()
        )
        signature = private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(data_to_verify: bytes, signature: str, public_key_pem: str) -> bool:
      
        try:
            public_key = load_pem_public_key(public_key_pem.encode())
            public_key.verify(
                base64.b64decode(signature),
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @staticmethod
    def build_note_signature_data(note) -> bytes:
     
        data = note.content_md.encode()

      
        for attachment in note.attachments:
            data += attachment.filename.encode('utf-8')
            data += str(attachment.size).encode('utf-8')
            data += attachment.encrypted_content

        return data

    @staticmethod
    def encrypt_attachment(file_data: bytes, password: str) -> bytes:
      
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        fernet = Fernet(key)
        return fernet.encrypt(file_data)

    @staticmethod
    def decrypt_attachment(encrypted_data: bytes, password: str) -> Optional[bytes]:
      
        try:
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_data)
        except Exception:
            return None

    @staticmethod
    def generate_random_key() -> bytes:
 
        return Fernet.generate_key()

    @staticmethod
    def encrypt_key(aes_key: bytes, public_key_pem: str) -> bytes:
        
        public_key = load_pem_public_key(public_key_pem.encode())
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key  

    @staticmethod
    def decrypt_key(encrypted_aes_key: bytes, private_key_pem: str) -> Optional[bytes]:
        
        try:
            from flask import current_app
            if not encrypted_aes_key or not private_key_pem:
                 return None

           
            private_key = load_pem_private_key(
                private_key_pem.encode(),
                password=current_app.config['SECRET_KEY'].encode()
            )
            
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key
        except Exception:
            return None

from flask_login import UserMixin
from datetime import datetime, timezone
from flask import session
from app import db
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app.services.crypto_service import CryptoService
 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    _totp_secret = db.Column('totp_secret',db.String(500), nullable=False)   
    notes = db.relationship('Note', backref='author', lazy=True)
   
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)

    @property
    def totp_secret(self):
        return CryptoService.decrypt_totp(self._totp_secret)
    
    @totp_secret.setter
    def totp_secret(self, value):
        self._totp_secret = CryptoService.encrypt_totp(value)

    @property
    def is_2fa_verified(self) -> bool:
        return session.get(f'2fa_verified_{self.id}', False)

    @is_2fa_verified.setter
    def is_2fa_verified(self, value: bool):
        session[f'2fa_verified_{self.id}'] = value
  
 
    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
 
        from flask import current_app
        encryption_algorithm = serialization.BestAvailableEncryption(
            current_app.config['SECRET_KEY'].encode()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.private_key = private_pem
        self.public_key = public_pem

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content_md = db.Column(db.Text, nullable=False)
    encrypted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    signature = db.Column(db.String(512), nullable=False)
    is_public = db.Column(db.Boolean, default=False)

    def is_accessible_by(self, user):
        if self.is_public or self.user_id == user.id:
            return True
        return SharedNote.query.filter_by(note_id=self.id, user_id=user.id).first() is not None   

       

class SharedNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)   
    shared_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=True) 

    note = db.relationship("Note", backref="shared_notes")
    user = db.relationship("User", backref="shared_notes")

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    size = db.Column(db.Integer, nullable=False)
    
    note = db.relationship("Note", backref=db.backref("attachments", cascade="all, delete-orphan"))





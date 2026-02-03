from typing import Optional
from werkzeug.utils import secure_filename
from app import db
from app.models import Note, User, SharedNote, Attachment
from .crypto_service import CryptoService


class NoteService:
 

    @staticmethod
    def send_message(
        sender: User,
        recipient: User,
        title: str,
        content: str,
        file_data: Optional[bytes] = None,
        filename: Optional[str] = None,
        mime_type: Optional[str] = None
    ) -> Note:
        aes_key = CryptoService.generate_random_key()
        aes_password = aes_key.decode('utf-8')
        note = Note(
            title=title,
            content_md=content,
            user_id=sender.id,
            is_public=False
        )

        if file_data and filename:
            secure_name = secure_filename(filename)
            encrypted_data = CryptoService.encrypt_attachment(file_data, aes_password)

            attachment = Attachment(
                filename=secure_name,
                mime_type=mime_type or 'application/octet-stream',
                encrypted_content=encrypted_data,
                size=len(file_data)
            )
            note.attachments.append(attachment)

        encrypted_content, _ = CryptoService.encrypt_content(content, aes_password)
        note.content_md = encrypted_content
        note.encrypted = True

        if not sender.private_key:
            sender.generate_keys()
            db.session.flush()

        NoteService.sign_note(note, sender)
        db.session.add(note)

        if not recipient.public_key:
             raise ValueError(f"Recipient {recipient.username} has no public key established.")

        encrypted_aes_key = CryptoService.encrypt_key(aes_key, recipient.public_key)

        shared_note = SharedNote(
            note=note,
            user=recipient,
            encrypted_aes_key=encrypted_aes_key
        )
        db.session.add(shared_note)
        db.session.commit()

        return note

    @staticmethod
    def sign_note(note: Note, user: User) -> None:
       
        if not user.private_key:
            raise ValueError("User has no private key")

         
        data_to_sign = CryptoService.build_note_signature_data(note)

       
        note.signature = CryptoService.sign_data(data_to_sign, user.private_key)

    @staticmethod
    def verify_note_signature(note: Note, user: User) -> bool:
        
        if not user.public_key or not note.signature:
            return False

        
        data_to_verify = CryptoService.build_note_signature_data(note)

       
        return CryptoService.verify_signature(data_to_verify, note.signature, user.public_key)

    @staticmethod
    def decrypt_note_content(note: Note, user: User) -> Optional[str]:
       
        if not note.encrypted:
            return note.content_md
 
        shared_note = SharedNote.query.filter_by(note_id=note.id, user_id=user.id).first()
        
    
        if not shared_note:
            return "[Encrypted Message - Content only readable by Recipient]"
           
            return "[Encrypted Message - Content only readable by Recipient]" 

        if not shared_note.encrypted_aes_key:
           
             return "[Legacy Message - Cannot Decrypt with Hybrid System]"

       
        aes_key = CryptoService.decrypt_key(shared_note.encrypted_aes_key, user.private_key)
        
        if not aes_key:
            return None

        aes_password = aes_key.decode('utf-8')
        return CryptoService.decrypt_content(note.content_md, aes_password)


    @staticmethod
    def mark_shared_note_read(shared_note: SharedNote) -> None:
        
        shared_note.is_read = True
        db.session.commit()

    @staticmethod
    def soft_delete_shared_note(shared_note: SharedNote) -> None:
       
        shared_note.is_deleted = True
        db.session.commit()

    @staticmethod
    def decrypt_attachment(attachment: Attachment, password: str) -> Optional[bytes]:
      
        return CryptoService.decrypt_attachment(attachment.encrypted_content, password)

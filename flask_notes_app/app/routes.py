import base64
import time
import uuid
from io import BytesIO

import pyotp
import pyqrcode

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    jsonify,
    send_file
)
from flask_login import login_user, logout_user, login_required, current_user

from app import db, limiter
from app.models import Note, User, SharedNote, Attachment
from app.forms import (
    LoginForm,
    Verify2FAForm,
    RegistrationForm,
    PasswordManager,
    SendMessageForm
)

from app.services import NoteService, CryptoService
 
def check_honeypot(request):
     
    honeypot = request.form.get('honeypot')
    if honeypot:
        abort(403)

main = Blueprint('main', __name__)

 

@main.route("/") 
def index():
    return redirect(url_for('main.login'))


@main.route("/login", methods=['GET', 'POST'])
@limiter.limit("15 per minute", key_func=lambda: f"login_global_{request.remote_addr}")   
@limiter.limit("5 per minute", key_func=lambda: f"login_user_{session.get('_id', 'anon')}")   
def login():
    check_honeypot(request)
    
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    
    form = LoginForm()
    
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0
        session['_id'] = str(uuid.uuid4())
        session['first_failed_time'] = None
        session['lockout_phase'] = 0
        session['lock_time'] = None

    lockout_durations = [30, 40, 50, 60]
    
    def check_lockout():
        if session.get('lock_time') is None:
            return False, None

        current_phase = min(session.get('lockout_phase', 0), len(lockout_durations) - 1)
        lockout_duration = lockout_durations[current_phase]

        elapsed = time.time() - session['lock_time']
        remaining = max(0, lockout_duration - elapsed)

        if remaining > 0:
            lock_end_timestamp = time.time() + remaining
            return True, int(lock_end_timestamp)
        else:
            session['lock_time'] = None
            session['failed_attempts'] = 0
            return False, None

    is_locked, lock_end_timestamp = check_lockout()

    if is_locked:
        flash(f'Too many failed attempts. Please try again in {int(lock_end_timestamp - time.time())} seconds', 'danger')
        return render_template('login.html',
                               form=form,
                               is_locked=True,
                               lock_end_timestamp=lock_end_timestamp)

    if session.get('failed_attempts', 0) > 0:
        delay = min(session['failed_attempts'], 5)
        time.sleep(delay)

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and PasswordManager.verify_password(user.password_hash, form.password.data):
            session.pop('failed_attempts', None)
            session.pop('lock_time', None)
            session.pop('lockout_phase', None)
            session.pop('first_failed_time', None)
            login_user(user)



            flash('Login successful!', 'success')
            return redirect(url_for('main.profile'))

        else:
            session['failed_attempts'] = session.get('failed_attempts', 0) + 1

            if session['failed_attempts'] == 1:
                session['first_failed_time'] = time.time()

            if session['failed_attempts'] % 5 == 0:
                session['lockout_phase'] = min(
                    session.get('lockout_phase', 0) + 1,
                    len(lockout_durations) - 1
                )
                session['lock_time'] = time.time()
                current_phase = session['lockout_phase'] - 1
                lockout_duration = lockout_durations[current_phase]

                 
                return render_template('login.html',
                                       form=form,
                                       is_locked=True,
                                       lock_end_timestamp=int(time.time() + lockout_duration))
            else:
                remaining_until_lockout = 5 - (session['failed_attempts'] % 5)
                flash(f'Invalid credentials. {remaining_until_lockout} attempts remaining before lockout.', 'danger')

    return render_template('login.html',
                           form=form,
                           is_locked=False,
                           lock_end_timestamp=None)


@main.route('/profile')
@login_required
def profile():
    if not current_user.is_2fa_verified:
        return redirect(url_for('main.verify_2fa'))
    
     
    inbox_messages = SharedNote.query.filter(
        SharedNote.user_id == current_user.id,
        SharedNote.is_deleted == False
    ).order_by(SharedNote.shared_at.desc()).all()
    
    return render_template(
        'profile.html',
        user=current_user,
        inbox_messages=inbox_messages
    )

 
@main.route('/logout')
@login_required
def logout():

    current_user.is_2fa_verified = False   
    db.session.commit()
    logout_user()  
    session.clear()   
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))


@main.route('/note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)

    
    if not note.is_accessible_by(current_user):
        flash("You do not have permission to access this note!", "danger")
        return redirect(url_for("main.profile"))

    signature_valid = NoteService.verify_note_signature(note, note.author)
    if not signature_valid:
        flash("WARNING: Digital signature invalid! The message may have been tampered with.", "danger")
        return redirect(url_for("main.profile"))

    if note.encrypted:
        decrypted_content = NoteService.decrypt_note_content(note, current_user)

        if decrypted_content:
            content_html = decrypted_content  
            note.signature_valid = signature_valid
            
            if current_user.id != note.user_id:
                shared = SharedNote.query.filter_by(note_id=note.id, user_id=current_user.id).first()
                if shared:
                    NoteService.mark_shared_note_read(shared)

            return render_template("note.html", note=note, content=content_html)
        else:
            flash("Failed to decrypt message (missing key or old format).", "danger")
            return render_template("note.html", note=note, content="[CONTENT ENCRYPTED - ACCESS DENIED]")

    note.content_html = note.content_md
    note.signature_valid = signature_valid

    if current_user.id != note.user_id:
        shared = SharedNote.query.filter_by(note_id=note.id, user_id=current_user.id).first()
        if shared:
            NoteService.mark_shared_note_read(shared)

    return render_template("note.html", note=note, content=note.content_html)

 

@main.route('/register', methods=['GET', 'POST'])
def register():
    check_honeypot(request)
    form = RegistrationForm()

    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists", 'error')
        elif User.query.filter_by(email=form.email.data).first():
            flash("Email already registered", 'error')
        else:
            try:
                user = User(
                    username=form.username.data,
                    email=form.email.data,
                    password_hash=PasswordManager.hash_password(form.password.data),
                    totp_secret=pyotp.random_base32()
                )
                user.generate_keys()
                db.session.add(user)
                db.session.commit()
                flash('Registration successful!', 'success')
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                flash(f'Registration error: {str(e)}', 'error')

    return render_template('register.html', form=form)

@main.route("/send", methods=["GET", "POST"])
@login_required
def send_message():
    form = SendMessageForm()
    if form.validate_on_submit():
        try:
            file = request.files.get('file')
            file_data = None
            filename = None
            mime_type = None

            if file and file.filename != '':
                filename = file.filename
                mime_type = file.mimetype
                file_data = file.read()
            
            recipient = User.query.filter_by(username=form.recipient.data).first()

            NoteService.send_message(
                sender=current_user,
                recipient=recipient,
                title=form.title.data,
                content=form.content.data,
                file_data=file_data,
                filename=filename,
                mime_type=mime_type
            )

            flash('Message sent successfully!', 'success')
            return redirect(url_for('main.profile'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error sending message: {str(e)}', 'danger')

    return render_template("send_message.html", form=form)


@main.route('/verify_2fa', methods=['GET', 'POST'])
@login_required   
def verify_2fa():
    form = Verify2FAForm()   


    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("Please enter the OTP code.", "error")
            return redirect(url_for('main.verify_2fa'))
        if form.validate_on_submit():
           otp = form.otp.data

        totp = pyotp.TOTP(current_user.totp_secret)
        
        if totp.verify(otp):
            current_user.is_2fa_verified = True
            db.session.commit()
            
            return redirect(url_for('main.profile'))
        else:
            flash("Invalid OTP code. Please try again.", "error")
    
     
    totp = pyotp.TOTP(current_user.totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.username,
        issuer_name="SecureNotes"
    )

     
    qr = pyqrcode.create(provisioning_uri)
    buffer = BytesIO()
    qr.png(buffer, scale=6)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
    return render_template('verify_2fa.html',
                           form=form, 
                           qr_code=qr_code_base64, 
                           secret=current_user.totp_secret)

 


@main.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

@main.route('/attachment/<int:attachment_id>', methods=['POST'])
@login_required
def download_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    note = attachment.note

    if not note.is_accessible_by(current_user):
        abort(403)

    if not note.encrypted:
        return send_file(
            BytesIO(attachment.encrypted_content),
            download_name=attachment.filename,
            mimetype=attachment.mime_type,
            as_attachment=True
        )

    shared_note = SharedNote.query.filter_by(note_id=note.id, user_id=current_user.id).first()
    
    if not shared_note or not shared_note.encrypted_aes_key:
        flash("Cannot decrypt attachment: Key not found.", "danger")
        return redirect(url_for('main.view_note', note_id=note.id))

    aes_key = CryptoService.decrypt_key(shared_note.encrypted_aes_key, current_user.private_key)
    if not aes_key:
         flash("Cannot decrypt attachment: Key decryption failed.", "danger")
         return redirect(url_for('main.view_note', note_id=note.id))
    
    aes_password = aes_key.decode('utf-8')

    decrypted_data = NoteService.decrypt_attachment(attachment, aes_password)
    if decrypted_data:
        return send_file(
            BytesIO(decrypted_data),
            download_name=attachment.filename,
            mimetype=attachment.mime_type,
            as_attachment=True
        )
    else:
        flash("Attachment decryption failed", "danger")
        return redirect(url_for('main.view_note', note_id=note.id))

@main.route('/delete_shared/<int:note_id>', methods=['POST'])
@login_required
def delete_shared_note(note_id):
    shared = SharedNote.query.filter_by(note_id=note_id, user_id=current_user.id).first_or_404()
    NoteService.soft_delete_shared_note(shared)
    flash('Message removed from inbox.', 'success')
    return redirect(url_for('main.profile'))

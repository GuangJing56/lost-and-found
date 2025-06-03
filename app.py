import os
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, current_app, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import event
from sqlalchemy.engine import Engine

load_dotenv()

# Flask extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()

# Enable foreign key constraints for SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# App factory
def create_app():
    app = Flask(__name__)
    basedir = os.path.abspath(os.path.dirname(__file__))

    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev_secret"),
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'lost_found.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.path.join(basedir, 'static', 'uploads'),
        ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'gif'},
        MAIL_SERVER=os.getenv("MAIL_SERVER"),
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER")
    )

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'login'

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    code_sent_at = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    items = db.relationship('LostItem', backref='owner', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)
    messages_sent = db.relationship('ChatMessage', backref='sender', lazy=True, foreign_keys='ChatMessage.sender_id')
    messages_received = db.relationship('ChatMessage', backref='receiver', lazy=True, foreign_keys='ChatMessage.receiver_id')
    

class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    photo = db.Column(db.String(200), nullable=True)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='lost')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reports = db.relationship('Report', backref='item', lazy=True, cascade="all, delete-orphan")
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    feedback_type = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id', ondelete='CASCADE'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)

# New ChatMessage model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png', 'gif'}

# Routes
def register_routes(app):
    @app.route('/')
    def about():
        return render_template('about.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username'].strip()
            email = request.form['email'].strip()
            password = request.form['password'].strip()

            if not email.endswith('@student.mmu.edu.my'):
                flash('Only @student.mmu.edu.my emails are allowed.', 'danger')
                return redirect(url_for('signup'))

            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('signup'))

            hashed = generate_password_hash(password)
            code = f"{random.randint(100000, 999999)}"

            user = User(username=username, email=email, password=hashed,
                        verification_code=code, code_sent_at=datetime.utcnow())
            db.session.add(user)
            db.session.commit()

            msg = Message('Your MMU Verification Code', recipients=[email])
            msg.body = f'Your verification code is: {code}'
            mail.send(msg)

            session['verify_email'] = email
            flash('A verification code has been sent to your email.', 'info')
            return redirect(url_for('verify_code'))

        return render_template('signup.html')

    @app.route('/verify', methods=['GET', 'POST'])
    def verify_code():
        email = session.get('verify_email')
        if not email:
            flash('Session expired. Please sign up again.', 'danger')
            return redirect(url_for('signup'))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('signup'))

        if request.method == 'POST':
            input_code = request.form['code'].strip()
            if datetime.utcnow() - user.code_sent_at > timedelta(minutes=10):
                flash('Verification code expired. Request a new one.', 'warning')
                return redirect(url_for('resend_code'))

            if input_code == user.verification_code:
                user.is_verified = True
                user.verification_code = None
                user.code_sent_at = None
                db.session.commit()
                flash('Email verified! You may now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Incorrect verification code.', 'danger')

        return render_template('verify_code.html', expiration=user.code_sent_at + timedelta(minutes=10))

    @app.route('/resend_code')
    def resend_code():
        email = session.get('verify_email')
        if not email:
            flash('Session expired. Please sign up again.', 'warning')
            return redirect(url_for('signup'))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('signup'))

        new_code = f"{random.randint(100000, 999999)}"
        user.verification_code = new_code
        user.code_sent_at = datetime.utcnow()
        db.session.commit()

        msg = Message('Your New MMU Verification Code', recipients=[email])
        msg.body = f'Your new verification code is: {new_code}'
        mail.send(msg)

        flash('A new code has been sent to your email.', 'info')
        return redirect(url_for('verify_code'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                if not user.is_verified:
                    flash('Please verify your email before logging in.', 'warning')
                    session['verify_email'] = user.email
                    return redirect(url_for('verify_code'))

                login_user(user)
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('browse'))

            flash('Invalid credentials.', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/browse')
    @login_required
    def browse():
        search = request.args.get('search', '').strip()
        status = request.args.get('status', 'all')
        date_str = request.args.get('date')

        query = LostItem.query.order_by(LostItem.date_reported.desc())

        if search:
           query = query.filter(
            (LostItem.name.ilike(f'%{search}%')) |
            (LostItem.description.ilike(f'%{search}%'))
        )
        if status != 'all':
           query = query.filter_by(status=status)
        if date_str:
          try:
              date = datetime.strptime(date_str, '%Y-%m-%d')
              query = query.filter(
                db.func.date(LostItem.date_reported) == date.date()
            )
          except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD.', 'warning')

        items = query.all()
        return render_template('browse.html', items=items)


    @app.route('/add_item', methods=['GET', 'POST'])
    @login_required
    def add_item():
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            phone = request.form['phone']
            status = request.form.get('status', 'lost')
            photo = request.files.get('photo')

            filename = None
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

            item = LostItem(name=name, description=description, phone=phone,
                            photo=filename, status=status, owner=current_user)
            db.session.add(item)
            db.session.commit()
            flash('Item added successfully.', 'success')
            return redirect(url_for('browse'))

        return render_template('add_item.html')

    @app.route('/delete_item/<int:item_id>', methods=['POST'])
    @login_required
    def delete_item(item_id):
        item = LostItem.query.get_or_404(item_id)
        # Admin or owner can delete
        if current_user.is_admin or item.user_id == current_user.id:
            try:
                db.session.delete(item)
                db.session.commit()
                flash('Item deleted successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error deleting item: {str(e)}', 'danger')
        else:
            abort(403)
        # Redirect where appropriate
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('browse'))

    @app.route('/admin/dashboard')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            abort(403)

        search = request.args.get('search', '').strip()
        status = request.args.get('status', 'all')

        query = LostItem.query.order_by(LostItem.date_reported.desc())
        if search:
            query = query.filter(
                (LostItem.name.ilike(f'%{search}%')) |
                (LostItem.description.ilike(f'%{search}%'))
            )
        if status != 'all':
            query = query.filter_by(status=status)

        items = query.all()

        feedbacks = Feedback.query.order_by(Feedback.date_submitted.desc()).all()
        reports = Report.query.order_by(Report.date_reported.desc()).all()

        return render_template('admin_dashboard.html', items=items, feedbacks=feedbacks, reports=reports)

    @app.route('/feedback', methods=['GET', 'POST'])
    @login_required
    def submit_feedback():
        if request.method == 'POST':
            feedback_type = request.form['feedback_type']
            content = request.form['content']
            feedback = Feedback(user_id=current_user.id, feedback_type=feedback_type, content=content)
            db.session.add(feedback)
            db.session.commit()
            flash('Feedback submitted successfully.', 'success')
            return redirect(url_for('browse'))
        return render_template('submit_feedback.html')

    @app.route('/report_item/<int:item_id>', methods=['GET', 'POST'])
    @login_required
    def report_item(item_id):
        item = LostItem.query.get_or_404(item_id)
        if request.method == 'POST':
            reason = request.form['reason']
            report = Report(user_id=current_user.id, item_id=item.id, reason=reason)
            db.session.add(report)
            db.session.commit()
            flash('Report submitted. Admin will review it.', 'info')
            return redirect(url_for('browse'))
        return render_template('report_item.html', item=item)
        

    # Chat routes
    @app.route('/chat')
    @login_required
    def chat():
        # List all users except current user to chat with
        users = User.query.filter(User.id != current_user.id).all()
        return render_template('chat.html', users=users)

    @app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
    @login_required
    def chat_with(user_id):
        other_user = User.query.get_or_404(user_id)
        if other_user.id == current_user.id:
            flash("You cannot chat with yourself.", "warning")
            return redirect(url_for('chat'))

        if request.method == 'POST':
            message_text = request.form['message'].strip()
            if message_text:
                message = ChatMessage(sender_id=current_user.id,
                                      receiver_id=other_user.id,
                                      message=message_text)
                db.session.add(message)
                db.session.commit()
                return redirect(url_for('chat_with', user_id=other_user.id))

        # Get messages between the two users ordered by timestamp ascending
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == other_user.id)) |
            ((ChatMessage.sender_id == other_user.id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.timestamp.asc()).all()

        return render_template('chat_room.html', other_user=other_user, messages=messages)

    # API endpoint to fetch new messages via AJAX for live chat (optional)
    @app.route('/chat/messages/<int:user_id>')
    @login_required
    def chat_messages(user_id):
        other_user = User.query.get_or_404(user_id)
        last_id = request.args.get('last_id', 0, type=int)

        messages = ChatMessage.query.filter(
            (((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == other_user.id)) |
             ((ChatMessage.sender_id == other_user.id) & (ChatMessage.receiver_id == current_user.id))) &
            (ChatMessage.id > last_id)
        ).order_by(ChatMessage.timestamp.asc()).all()

        messages_data = [
            {
                "id": m.id,
                "sender": m.sender.username,
                "message": m.message,
                "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "is_sender": (m.sender_id == current_user.id)
            } for m in messages
        ]

        return jsonify(messages_data)

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)

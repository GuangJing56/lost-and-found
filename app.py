import os
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, send_file, current_app, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from io import BytesIO, StringIO
from fpdf import FPDF
import csv
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
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    code_sent_at = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    warnings = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    items = db.relationship('LostItem', backref='owner', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)
    messages_sent = db.relationship('ChatMessage', backref='sender', lazy=True, foreign_keys='ChatMessage.sender_id')
    messages_received = db.relationship('ChatMessage', backref='receiver', lazy=True, foreign_keys='ChatMessage.receiver_id')

class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.String(500), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(150))
    photo = db.Column(db.String(200), nullable=True)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='lost')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    reports = db.relationship('Report', backref='item', lazy=True, cascade="all, delete-orphan")

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    feedback_type = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, default=0)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id', ondelete='CASCADE'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)

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
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

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

                if user.is_banned:
                    flash('Your account has been banned. Contact admin for support.', 'danger')
                    return redirect(url_for('login'))

                login_user(user)
                flash(f'Welcome back, {user.username}!', 'success')
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
        category = request.args.get('category', 'all')
        status = request.args.get('status', 'all')
        date_str = request.args.get('date')

        query = LostItem.query.order_by(LostItem.date_reported.desc())

        if search:
            query = query.filter(
                (LostItem.name.ilike(f'%{search}%')) |
                (LostItem.description.ilike(f'%{search}%'))
            )
        if category != 'all':
            query = query.filter_by(category=category)
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
            name = request.form['person name']
            description = request.form['description']
            phone = request.form['phone']
            location = request.form['location']
            category = request.form['category']
            status = request.form.get('status', 'lost')
            photo = request.files.get('photo')

            filename = None
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

            item = LostItem(
                name=name,
                description=description,
                phone=phone,
                location=location,
                status=status,
                category=category,
                photo=filename,
                owner=current_user
            )
            db.session.add(item)
            db.session.commit()
            flash('Item added successfully.', 'success')
            return redirect(url_for('browse'))

        return render_template('add_item.html')

    @app.route('/delete_item/<int:item_id>', methods=['POST'])
    @login_required
    def delete_item(item_id):
        item = LostItem.query.get_or_404(item_id)
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
        users = User.query.all()

        return render_template('admin_dashboard.html',
                            items=items,
                            feedbacks=feedbacks,
                            reports=reports,
                            users=users)

    @app.route('/feedback', methods=['GET', 'POST'])
    @login_required
    def submit_feedback():
        if request.method == 'POST':
            feedback_type = request.form['feedback_type']
            content = request.form['content']
            feedback = Feedback(
                user_id=current_user.id,
                feedback_type=feedback_type,
                content=content,
            )
            db.session.add(feedback)
            db.session.commit()
            flash('Feedback submitted successfully.', 'success')
            return redirect(url_for('browse'))
        
        feedbacks = Feedback.query.order_by(Feedback.upvotes.desc()).all()
        return render_template('submit_feedback.html', feedbacks=feedbacks)

    @app.route('/upvote/<int:feedback_id>')
    @login_required
    def upvote(feedback_id):
        fb = Feedback.query.get_or_404(feedback_id)
        fb.upvotes += 1
        db.session.commit()
        return redirect(url_for('submit_feedback'))

    @app.route('/downvote/<int:feedback_id>')
    @login_required
    def downvote(feedback_id):
        fb = Feedback.query.get_or_404(feedback_id)
        fb.downvotes += 1
        db.session.commit()
        return redirect(url_for('submit_feedback'))

    @app.route('/report_item/<int:item_id>', methods=['GET', 'POST'])
    @login_required
    def report_item(item_id):
        item = LostItem.query.get_or_404(item_id)
        if request.method == 'POST':
            reason = request.form['reason']
            report = Report(
                user_id=current_user.id,
                item_id=item.id,
                reason=reason
            )
            db.session.add(report)
            db.session.commit()
            flash('Report submitted. Admin will review it.', 'info')
            return redirect(url_for('browse'))
        return render_template('report_item.html', item=item)

    @app.route('/admin/delete_feedback/<int:feedback_id>', methods=['POST'])
    @login_required
    def delete_feedback(feedback_id):
        if not current_user.is_admin:
            abort(403)
        fb = Feedback.query.get_or_404(feedback_id)
        db.session.delete(fb)
        db.session.commit()
        flash('Feedback deleted.', 'info')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/delete_report/<int:report_id>', methods=['POST'])
    @login_required
    def delete_report(report_id):
        if not current_user.is_admin:
            abort(403)
        rpt = Report.query.get_or_404(report_id)
        db.session.delete(rpt)
        db.session.commit()
        flash('Report deleted.', 'info')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/warn_user/<int:user_id>', methods=['POST'])
    @login_required
    def warn_user(user_id):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        user.warnings += 1
        if user.warnings >= 3:
            user.is_banned = True
        db.session.commit()
        flash(f'User {user.username} warned.', 'warning')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/unban_user/<int:user_id>', methods=['POST'])
    @login_required
    def unban_user(user_id):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        user.is_banned = False
        user.warnings = 0
        db.session.commit()
        flash(f'User {user.username} unbanned.', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/download_pdf')
    @login_required
    def download_pdf():
        if not current_user.is_admin:
            abort(403)
        
        buffer = BytesIO()
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Lost and Found Report", ln=True, align='C')

        items = LostItem.query.all()
        for item in items:
            pdf.cell(200, 10, txt=f"{item.name} - {item.status}", ln=True)

        pdf_bytes = pdf.output(dest='S').encode('latin1')
        buffer = BytesIO(pdf_bytes)
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name="report.pdf",
            mimetype='application/pdf'
        )

    @app.route('/admin/download_csv')
    @login_required
    def download_csv():
        if not current_user.is_admin:
            abort(403)

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Name', 'Category', 'Status', 'Location', 'Date Reported', 'Reported By'])

        items = LostItem.query.all()
        for item in items:
            writer.writerow([
                item.id,
                item.name,
                item.category,
                item.status,
                item.location,
                item.date_reported.strftime('%d/%m/%Y'),
                item.owner.username if item.owner else 'N/A'
            ])

        output.seek(0)
        return send_file(
            BytesIO(output.getvalue().encode()),
            as_attachment=True,
            download_name="lost_items.csv",
            mimetype='text/csv'
        )

    # Chat routes
    @app.route('/chat')
    @login_required
    def chat():
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
                message = ChatMessage(
                    sender_id=current_user.id,
                    receiver_id=other_user.id,
                    message=message_text
                )
                db.session.add(message)
                db.session.commit()
                return redirect(url_for('chat_with', user_id=other_user.id))

        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == other_user.id)) |
            ((ChatMessage.sender_id == other_user.id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.timestamp.asc()).all()

        return render_template('chat_room.html', other_user=other_user, messages=messages)

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
# Test change: add this line to test git commit
# lostnfound.py
import os
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, send_file
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

load_dotenv()

app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev_secret"),
    SQLALCHEMY_DATABASE_URI='sqlite:///lost_found.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'gif'},
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER")
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    code_sent_at = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    warnings = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    items = db.relationship('LostItem', backref='owner', lazy=True)

class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    category = db.Column(db.String(100))
    description = db.Column(db.String(500))
    phone = db.Column(db.String(20))
    location = db.Column(db.String(150))
    status = db.Column(db.String(50), default="lost")
    photo = db.Column(db.String(200))
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    rating = db.Column(db.Integer, default=0)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='feedback')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id'))
    reason = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    item = db.relationship('LostItem', backref = 'reports')
    user = db.relationship('User', backref='reports')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
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
            flash('Only @student.mmu.edu.my emails allowed.', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email exists.', 'danger')
            return redirect(url_for('signup'))

        code = f"{random.randint(100000,999999)}"
        user = User(username=username, email=email,
                    password=generate_password_hash(password),
                    verification_code=code, code_sent_at=datetime.utcnow())
        db.session.add(user)
        db.session.commit()

        msg = Message('MMU Verification Code', recipients=[email])
        msg.body = f"Your verification code: {code}"
        mail.send(msg)

        session['verify_email'] = email
        flash('Verification code sent to email.', 'info')
        return redirect(url_for('verify'))

    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    email = session.get('verify_email')
    if not email:
        return redirect(url_for('signup'))
    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        input_code = request.form['code']
        if datetime.utcnow() - user.code_sent_at > timedelta(minutes=10):
            flash('Code expired.', 'danger')
            return redirect(url_for('resend_code'))
        if input_code == user.verification_code:
            user.is_verified = True
            user.verification_code = None
            db.session.commit()
            flash('Verified. You may log in.', 'success')
            return redirect(url_for('login'))
        flash('Wrong code.', 'danger')
    return render_template('verify_code.html', expiration=user.code_sent_at + timedelta(minutes=10))

@app.route('/resend_code')
def resend_code():
    email = session.get('verify_email')
    user = User.query.filter_by(email=email).first()
    new_code = f"{random.randint(100000,999999)}"
    user.verification_code = new_code
    user.code_sent_at = datetime.utcnow()
    db.session.commit()
    msg = Message('Resend Code', recipients=[email])
    msg.body = f"Your new code: {new_code}"
    mail.send(msg)
    flash('New code sent.', 'info')
    return redirect(url_for('verify'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        if not user.is_verified:
            session['verify_email'] = user.email
            flash('Please verify your email before logging in.', 'warning')
            return redirect(url_for('verify_code'))

        if user.is_banned:
            flash('Your account has been banned. Contact admin for support.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('admin_dashboard') if user.is_admin else url_for('browse'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/browse')
@login_required
def browse():
    search = request.args.get('search', '')
    category = request.args.get('category', 'all')
    status = request.args.get('status', 'all')

    query = LostItem.query
    if search:
        query = query.filter(LostItem.name.ilike(f'%{search}%'))
    if category != 'all':
        query = query.filter_by(category=category)
    if status != 'all':
        query = query.filter_by(status=status)

    items = query.order_by(LostItem.date_reported.desc()).all()
    return render_template('browse.html', items=items)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        phone = request.form['phone']
        location = request.form['location']
        category = request.form['category']
        status = request.form.get('status', 'lost')
        photo = request.files.get('photo')

        filename = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        item = LostItem(name=name, description=description, phone=phone,
                        location=location, status=status, category=category,
                        photo=filename, owner=current_user)
        db.session.add(item)
        db.session.commit()
        flash('Item added.', 'success')
        return redirect(url_for('browse'))
    return render_template('add_item.html')

@app.route('/report_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def report_item(item_id):
    item = LostItem.query.get_or_404(item_id)
    if request.method == 'POST':
        reason = request.form['reason']
        report = Report(user_id=current_user.id, item_id=item_id, reason=reason)
        db.session.add(report)
        db.session.commit()
        flash('Report submitted.', 'info')
        return redirect(url_for('browse'))
    return render_template('report_item.html', item=item)

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def submit_feedback():
    if request.method == 'POST':
        content = request.form['content']
        fb = Feedback(content=content, user_id=current_user.id)
        db.session.add(fb)
        db.session.commit()
        flash('Thanks for your feedback!', 'success')
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

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    items = LostItem.query.all()
    feedbacks = Feedback.query.all()
    reports = Report.query.all()
    users = User.query.all()
    return render_template('admin_dashboard.html', items=items, feedbacks=feedbacks, reports=reports, users=users)

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = LostItem.query.get_or_404(item_id)
    if current_user.is_admin or item.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted successfully.', 'success')
    else:
        abort(403)
    return redirect(url_for('browse'))

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
    return send_file(buffer, as_attachment=True, download_name="report.pdf", mimetype='application/pdf')

@app.route('/admin/download_csv')
@login_required
def download_csv():
    if not current_user.is_admin:
        abort(403)

    output = StringIO()
    writer = csv.writer(output)

    # CSV headers
    writer.writerow(['ID', 'Name', 'Category', 'Status', 'Location', 'Date Reported', 'Reported By'])

    # Add item data
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
    return send_file(BytesIO(output.getvalue().encode()), as_attachment=True, download_name="lost_items.csv", mimetype='text/csv')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

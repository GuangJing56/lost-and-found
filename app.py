import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Configuration
basedir = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev_secret_key'),
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'lost_found.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.path.join(basedir, 'static', 'uploads'),
        ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'gif'}
    )

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        db.create_all()

    register_routes(app)

    @app.errorhandler(404)
    def not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('500.html'), 500

    return app

# Extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Models
class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    photo = db.Column(db.String(200), nullable=True)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    items = db.relationship('LostItem', backref='owner', lazy='dynamic')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def register_routes(app):
    @app.route('/')
    def about():
        return render_template('about.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username'].strip()
            password = request.form['password'].strip()
            if not username or not password:
                flash('Username and password are required.', 'danger')
                return redirect(url_for('signup'))
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return redirect(url_for('signup'))
            hashed = generate_password_hash(password)
            user = User(username=username, password=hashed)
            db.session.add(user)
            db.session.commit()
            flash('Account created. Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('browse'))
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/browse')
    def browse():
        items = LostItem.query.order_by(LostItem.date_reported.desc()).all()
        return render_template('browse.html', items=items)

    @app.route('/add_item', methods=['GET', 'POST'])
    @login_required
    def add_item():
        if request.method == 'POST':
            name = request.form['name'].strip()
            description = request.form['description'].strip()
            phone = request.form['phone'].strip()
            if not name or not description or not phone:
                flash('All fields except photo are required.', 'danger')
                return redirect(url_for('add_item'))
            filename = None
            photo = request.files.get('photo')
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item = LostItem(name=name, description=description,
                            phone=phone, photo=filename,
                            owner=current_user)
            db.session.add(item)
            db.session.commit()
            flash('Item reported successfully.', 'success')
            return redirect(url_for('browse'))
        return render_template('add_item.html')

    @app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
    @login_required
    def edit_item(item_id):
        item = LostItem.query.get_or_404(item_id)
        if item.owner != current_user:
            abort(403)
        if request.method == 'POST':
            item.name = request.form['name'].strip()
            item.description = request.form['description'].strip()
            item.phone = request.form['phone'].strip()
            db.session.commit()
            flash('Item updated.', 'success')
            return redirect(url_for('browse'))
        return render_template('edit_item.html', item=item)

    @app.route('/delete_item/<int:item_id>', methods=['POST'])
    @login_required
    def delete_item(item_id):
        item = LostItem.query.get_or_404(item_id)
        if item.owner != current_user:
            abort(403)
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted.', 'success')
        return redirect(url_for('browse'))

    @app.route('/admin_signup', methods=['GET', 'POST'])
    @login_required
    def admin_signup():
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))

        if request.method == 'POST':
            username = request.form['username'].strip()
            password = request.form['password'].strip()

            if not username or not password:
                flash('Username and password cannot be empty.', 'danger')
                return redirect(url_for('admin_signup'))

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return redirect(url_for('admin_signup'))

            hashed = generate_password_hash(password)
            user = User(username=username, password=hashed, is_admin=True)
            db.session.add(user)
            db.session.commit()
            flash('Admin account created successfully.', 'success')
            return redirect(url_for('login'))

        return render_template('admin_signup.html')

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)

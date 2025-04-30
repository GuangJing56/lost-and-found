from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# 丢失物品模型
class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    photo = db.Column(db.String(100), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 允许上传的文件
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 路由
@app.route('/')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('about'))
        else:
            flash('Login Failed. Check username and/or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        phone = request.form['phone']
        photo = request.files['photo']

        # Save photo if provided
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_item = LostItem(name=name, description=description, phone=phone, photo=filename)
        else:
            new_item = LostItem(name=name, description=description, phone=phone)

        db.session.add(new_item)
        db.session.commit()
        flash('Item added successfully', 'success')
        return redirect(url_for('items'))

    return render_template('add_item.html')

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = LostItem.query.get_or_404(item_id)
    
    # Check if the current user is the one who added the item
    if item.user_id != current_user.id:
        flash("You can only edit your own items", "danger")
        return redirect(url_for('items'))

    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.phone = request.form['phone']
        db.session.commit()
        flash('Item updated successfully', 'success')
        return redirect(url_for('items'))

    return render_template('edit_item.html', item=item)

@app.route('/delete_item/<int:item_id>')
@login_required
def delete_item(item_id):
    item = LostItem.query.get_or_404(item_id)
    
    # Check if the current user is the one who added the item
    if item.user_id != current_user.id:
        flash("You can only delete your own items", "danger")
        return redirect(url_for('items'))

    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully', 'success')
    return redirect(url_for('items'))

@app.route('/items')
@login_required  
def items():
    items = LostItem.query.all()
    return render_template('items.html', items=items)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

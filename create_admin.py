# create_admin.py
from lostnfound import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()  # Ensure tables are created

    username = 'admin13579'
    email = 'admin@localhost'
    password = 'admin12345678'

    if User.query.filter_by(username=username).first():
        print("Admin user already exists.")
    else:
        hashed_password = generate_password_hash(password)
        admin = User(username=username, email=email,
                     password=hashed_password, is_admin=True,
                     is_verified=True)
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin account created successfully.")

from werkzeug.security import generate_password_hash
import sqlite3

# Admin details
username = 'admin13579'
email = 'admin@localhost'  # Dummy email to satisfy NOT NULL constraint
password = 'admin12345678'
is_admin = 1
is_verified = 1

# Hash the password
hashed_password = generate_password_hash(password)

# Connect to the database
conn = sqlite3.connect('lost_found.db')
c = conn.cursor()

# Check if the user already exists
c.execute("SELECT * FROM user WHERE username = ?", (username,))
if c.fetchone():
    print("Admin user already exists.")
else:
    # Insert admin with dummy email
    c.execute("""
        INSERT INTO user (username, email, password, is_admin, is_verified)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, hashed_password, is_admin, is_verified))

    conn.commit()
    print("Admin account created successfully.")

conn.close()

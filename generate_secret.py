import os

def generate_secret_key():
    # Generate a random 24-byte key and convert it to a hexadecimal string
    secret_key = os.urandom(24).hex()
    return secret_key

def main():
    # Generate and print the SECRET_KEY
    secret_key = generate_secret_key()
    print(f"Generated SECRET_KEY: {secret_key}")
    print("\nCopy this value and add it to your .env file.")

if __name__ == "__main__":
    main()

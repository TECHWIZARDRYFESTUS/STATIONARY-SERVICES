from getpass import getpass

from .auth import hash_password
from .database import Base, SessionLocal, engine
from . import models

def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(models.User).filter_by(role="admin").first():
            raise SystemExit("An administrator already exists. Sign in with an admin account.")
        name = input("Administrator name: ").strip()
        email = input("Administrator email: ").strip().lower()
        password = getpass("Password (12-72 UTF-8 bytes): ")
        confirmation = getpass("Confirm password: ")
        if len(name) < 2:
            raise SystemExit("Name must contain at least 2 characters.")
        if "@" not in email or len(email) > 160:
            raise SystemExit("Enter a valid email address.")
        if len(password) < 12:
            raise SystemExit("Password must contain at least 12 characters.")
        if len(password.encode("utf-8")) > 72:
            raise SystemExit("Password must contain no more than 72 UTF-8 bytes for bcrypt.")
        if password != confirmation:
            raise SystemExit("Passwords do not match.")
        if db.query(models.User).filter_by(email=email).first():
            raise SystemExit("An account already uses that email address.")
        db.add(models.User(
            name=name,
            email=email,
            password_hash=hash_password(password),
            role="admin",
            active=True,
        ))
        db.commit()
        print("Administrator account created. Start the server and sign in.")
    finally:
        db.close()

if __name__ == "__main__":
    main()

import argparse
from getpass import getpass

from . import models
from .auth import hash_password
from .database import SessionLocal


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset an administrator password.")
    parser.add_argument(
        "--new-email",
        help="also change the administrator login email",
    )
    args = parser.parse_args()

    current_email = input("Current administrator email: ").strip().lower()
    new_email = (args.new_email or current_email).strip().lower()
    password = getpass("New password (12-72 UTF-8 bytes): ")
    confirmation = getpass("Confirm new password: ")

    if "@" not in new_email or len(new_email) > 160 or any(char.isspace() for char in new_email):
        raise SystemExit("Enter a valid email address.")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    if len(password.encode("utf-8")) > 72:
        raise SystemExit("Password must contain no more than 72 UTF-8 bytes for bcrypt.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    db = SessionLocal()
    try:
        account = db.query(models.User).filter_by(email=current_email, role="admin").first()
        if not account:
            raise SystemExit("No administrator account found with the current email.")
        if new_email != current_email and db.query(models.User).filter_by(email=new_email).first():
            raise SystemExit("Another account already uses the new email address.")
        account.email = new_email
        account.password_hash = hash_password(password)
        db.add(models.AuditLog(
            action="admin.credentials_reset",
            details=f"user_id={account.id}",
        ))
        db.commit()
        print(f"Administrator credentials updated for {new_email}. Sign in with the new email and password.")
    finally:
        db.close()


if __name__ == "__main__":
    main()

"""Create a bootstrap admin user for local/UI testing (Phase 2).

Usage: PYTHONPATH=. python scripts/bootstrap_admin.py
"""

from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import User
from app.security import hash_password


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        existing = db.execute(
            select(User).where(User.email == "admin@demo.local")
        ).scalar_one_or_none()
        if existing:
            print(f"Admin already exists: id={existing.id} email={existing.email}")
            return
        admin = User(
            email="admin@demo.local",
            name="Demo Admin",
            password_hash=hash_password("demo-admin-pass"),
            role="admin",
            is_active=True,
        )
        reviewer = User(
            email="reviewer_a@demo.local",
            name="Reviewer A",
            password_hash=hash_password("demo-reviewer-pass"),
            role="reviewer",
            is_active=True,
        )
        reviewer_b = User(
            email="reviewer_b@demo.local",
            name="Reviewer B",
            password_hash=hash_password("demo-reviewer-pass"),
            role="reviewer",
            is_active=True,
        )
        auditor = User(
            email="auditor@demo.local",
            name="Auditor",
            password_hash=hash_password("demo-auditor-pass"),
            role="auditor",
            is_active=True,
        )
        db.add_all([admin, reviewer, reviewer_b, auditor])
        db.commit()
        print("Created users:")
        print("  admin@demo.local / demo-admin-pass")
        print("  reviewer_a@demo.local / demo-reviewer-pass")
        print("  reviewer_b@demo.local / demo-reviewer-pass")
        print("  auditor@demo.local / demo-auditor-pass")
    finally:
        db.close()


if __name__ == "__main__":
    main()

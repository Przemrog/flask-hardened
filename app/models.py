from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):  # [HARDENING A07] UserMixin -> integracja z Flask-Login
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="USER")
    avatar_path = db.Column(db.String(255))


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    owner = db.relationship("User", backref="notes")
    title = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, default="")
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


def seed_data():
    if User.query.count() > 0:
        return
    admin = User(email="admin@local", password_hash=generate_password_hash("admin123"), role="ADMIN")
    alice = User(email="alice@local", password_hash=generate_password_hash("alice123"), role="USER")
    bob = User(email="bob@local", password_hash=generate_password_hash("bob123"), role="USER")
    db.session.add_all([admin, alice, bob])
    db.session.commit()
    db.session.add_all([
        Note(owner_id=alice.id, title="Lista zakupow", body="mleko, chleb, kawa"),
        Note(owner_id=alice.id, title="Haslo do routera", body="prywatna notatka Alicji"),
        Note(owner_id=bob.id, title="Pomysly na projekt", body="prywatna notatka Boba"),
        Note(owner_id=admin.id, title="Notatka administratora", body="tylko dla admina"),
    ])
    db.session.commit()

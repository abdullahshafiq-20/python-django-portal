from flask_login import UserMixin
from datetime import datetime
from . import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(150))
    phone_number = db.Column(db.String(20))
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_created_at = db.Column(db.DateTime, nullable=True)


class Image(db.Model):
    __tablename__ = "images"

    id = db.Column(db.Integer, primary_key=True)
    posted_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    filetype = db.Column(db.String(10))
    image = db.Column(db.LargeBinary)
    comments = db.Column(db.String(1024))

class PasswordReset(db.Model):
    __tablename__ = "password_resets"
    
    id = db.Column(db.Integer, primary_key=True)
    for_user = db.Column(db.Integer, db.ForeignKey("users.id"))
    token = db.Column(db.String(64))
    has_reset = db.Column(db.Boolean, default=False)
    requested = db.Column(db.DateTime, default=datetime.utcnow)

class Evaluation(db.Model):
    __tablename__ = "evaluations"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    item_description = db.Column(db.String(1024))
    item_photos = db.Column(db.String(512))  # Comma-separated photo IDs
    contact_preference = db.Column(db.String(20))  # 'email' or 'phone'
    contact_time = db.Column(db.String(20), nullable=True)  # For phone contact preference
    estimated_value = db.Column(db.Float)
    evaluator_notes = db.Column(db.String(1024))
    status = db.Column(db.String(20), default="pending")  # pending, completed, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
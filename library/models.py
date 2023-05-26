import uuid

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


# users table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(
        db.String(40),
        unique=True,
        default=str(uuid.uuid4()),
        nullable=False,
        name="user_unique_id",
    )
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(128))
    admin = db.Column(db.Boolean)
    name = db.Column(db.String(100))
    permission = db.Column(db.String(100), default="user")

    def __repr__(self):
        return "<User {}>".format(self.username)

    def __init__(self, username, password, admin=False, name="", permission="user"):
        self.username = username
        self.password = generate_password_hash(password)
        self.admin = admin
        self.name = name if name else username
        self.permission = permission

    def check_password(self, password):
        return check_password_hash(self.password, password)

from sqlalchemy.orm import backref
from flask import request, jsonify, make_response
from library.main  import app, db
from functools import wraps
import jwt
# from flask_restful import abor
import uuid
from werkzeug.security import check_password_hash, generate_password_hash

# users table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(40),unique=True,default=str(uuid.uuid4()),  nullable=False, name="user_unique_id" )
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(128))
    admin = db.Column(db.Boolean)
    name=db.Column(db.String(100))
    permission=db.Column(db.String(100),default='user')
    def __repr__(self):
        return '<User {}>'.format(self.username)

    def __init__(self, username, password, admin=False, name='', permission='user'):
        self.username = username
        self.password =  generate_password_hash(password)
        self.admin = admin
        self.name = name if name else username
        self.permission = permission
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

# token decorator
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        # pass jwt-token in headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token: # throw error if no token provided
            return make_response(jsonify({"message": "A valid token is missing!"}), 401)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return make_response(jsonify({"message": "Invalid token!"}), 401)

        return f( *args, **kwargs)
    return decorator

def permission_required(permission):
    def deco(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = None
            # pass jwt-token in headers
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']
            if not token: # throw error if no token provided
                return make_response(jsonify({"message": "A valid token is missing!"}), 401)
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = User.query.filter_by(public_id=data['public_id']).first()
                current_user_permissions = current_user.permission
            except:
                return make_response(jsonify({"message": "Invalid token"}), 401)
            
            if not current_user_permissions or not (current_user_permissions in permission):
                return make_response({"message": "Not authorized", })
            return f(*args, **kwargs)
        return decorator
    return deco

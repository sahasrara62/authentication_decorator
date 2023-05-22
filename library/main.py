import os

from flask import Flask
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

metadata = MetaData(
    naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
    }
)

from config import app_config
config_name = os.getenv('FLASK_ENV', 'default')

# db = SQLAlchemy()

# def get_app():
#     app = Flask(__name__)
#     app.config.from_object(app_config[config_name])

app = Flask(__name__)
# app.config.from_object(Config)
app.config.from_object(app_config[config_name])
db = SQLAlchemy(app, metadata=metadata)
# cli = FlaskGroup(create_app=app)
api = Api(app)
migrate = Migrate(app, db)




# @app.before_first_request
# def create_tables():
#     db.create_all()

# migrate = Migrate(app, db, render_as_batch=True) # obj for db migrations
# CORS(app)

# from library import models, resources

from flask import request, jsonify, make_response
import jwt
from library.main import db, app
from library.models import User, token_required, permission_required


@app.route('/users/signup', methods=['POST'])
@token_required
@permission_required(["admin"])
def signup_user():
    data=request.get_json()
    # hashed_password = generate_password_hash(data['password'], method='sha256')

    user=User.query.filter_by(username=data['username']).first()
    if not user:
        new_user=User(username=data['username'], password=data['password'], admin=False, permission=data[
            'permission'])
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'registered successfully'}), 201
    else:
        return make_response(jsonify({"message": "User already exists!"}), 409)


# user login route
@app.route('/login', methods=['POST'])
def login():
    auth=request.get_json()
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic-realm= "Login required!"'})

    user=User.query.filter_by(username=auth['username']).first()
    if not user:
        return make_response('Could not verify user!', 401, {'WWW-Authenticate': 'Basic-realm= "No user found!"'})

    if user.check_password(auth.get('password')):
        token=jwt.encode({'public_id': user.public_id}, app.config['SECRET_KEY'], 'HS256')
        return make_response(jsonify({'token': token}), 201)
    return make_response('Could not verify password!', 403, {'WWW-Authenticate': 'Basic-realm= "Wrong Password!"'})


@app.route('/users/details/<username>', methods=['GET'])
@token_required
@permission_required(['admin', 'user'])
def get_details(username):
    user=User.query.filter_by(username=username).first()
    if not user:
        return {"message": "user not found"}, 400

    user_details={"user_name": user.username,
                  "name": user.name,
                  "user_id": user.public_id,

                  }
    return jsonify({"details": user_details})


@app.route('/users/delete/<username>', methods=['DELETE'])
@token_required
@permission_required(['admin'])
def delete_users(username):
    user=User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'user does not exist'})

    if user.admin:
        return jsonify({'message': 'can\'t delete admin profile'}), 400
    try:
        db.session.delete(user)
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({'message': "unable to delete user account... try again"})
    return jsonify({'message': 'user deleted'})


@app.route("/users/update/<username>/<name>", methods=['PUT'])
@token_required
@permission_required(['admin', 'user'])
def update_name(username, name):
    user=User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': "Invalid username"})
    try:
        user.name=name
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({"messgae": "Error occur ... Unable to update"}), 401
    return jsonify({"message": "name is updated successfully."})

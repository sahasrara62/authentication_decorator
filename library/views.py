import jwt
from flask import blueprints, jsonify, make_response, request

from config import Config
from library.models import db, User
from library.utils import permission_required, token_required

app_route = blueprints.Blueprint("users", __name__, url_prefix="/users")


@app_route.route("/signup", methods=["POST"])
@token_required
@permission_required(["admin"])
def signup_user():
    data = request.get_json()

    user = User.query.filter_by(username=data["username"]).first()
    if not user:
        new_user = User(
            username=data["username"],
            password=data["password"],
            admin=False,
            permission=data["permission"],
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "registered successfully"}), 201
    else:
        return make_response(jsonify({"message": "User already exists!"}), 409)


# user login route
@app_route.route("/login", methods=["POST"])
def login():
    auth = request.get_json()
    if not auth or not auth.get("username") or not auth.get("password"):
        return make_response(
            "Could not verify!",
            401,
            {"WWW-Authenticate": 'Basic-realm= "Login required!"'},
        )

    user = User.query.filter_by(username=auth["username"]).first()
    if not user:
        return make_response(
            "Could not verify user!",
            401,
            {"WWW-Authenticate": 'Basic-realm= "No user found!"'},
        )

    if user.check_password(auth.get("password")):
        token = jwt.encode({"public_id": user.public_id}, Config.SECRET_KEY, "HS256")
        return make_response(jsonify({"token": token}), 201)
    return make_response(
        "Could not verify password!",
        403,
        {"WWW-Authenticate": 'Basic-realm= "Wrong Password!"'},
    )


@app_route.route("/details/<username>", methods=["GET"])
@token_required
@permission_required(["admin", "user"])
def get_details(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return {"message": "user not found"}, 400

    user_details = {
        "user_name": user.username,
        "name": user.name,
        "user_id": user.public_id,
    }
    return jsonify({"details": user_details})


@app_route.route("/delete/<username>", methods=["DELETE"])
@token_required
@permission_required(["admin"])
def delete_users(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "user does not exist"})

    if user.admin:
        return jsonify({"message": "can't delete admin profile"}), 400
    try:
        db.session.delete(user)
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({"message": "unable to delete user account... try again"})
    return jsonify({"message": "user deleted"})


@app_route.route("/update/<username>/<name>", methods=["PUT"])
@token_required
@permission_required(["admin", "user"])
def update_name(username, name):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Invalid username"})
    try:
        user.name = name
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({"messgae": "Error occur ... Unable to update"}), 401
    return jsonify({"message": "name is updated successfully."})

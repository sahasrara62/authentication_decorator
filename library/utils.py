from functools import wraps

import jwt
from flask import jsonify, make_response, request

from config import Config
# from flask_restful import abor
from library.models import User


# token decorator
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        # pass jwt-token in headers
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:  # throw error if no token provided
            return make_response(jsonify({"message": "A valid token is missing!"}), 401)
        try:
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except:
            return make_response(jsonify({"message": "Invalid token!"}), 401)
        return f(*args, **kwargs)
    return decorator


def permission_required(permission):
    def deco(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = None
            # pass jwt-token in headers
            if "x-access-token" in request.headers:
                token = request.headers["x-access-token"]
            if not token:  # throw error if no token provided
                return make_response(
                    jsonify({"message": "A valid token is missing!"}), 401
                )
            try:
                data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
                current_user = User.query.filter_by(public_id=data["public_id"]).first()
                current_user_permissions = current_user.permission
            except:
                return make_response(jsonify({"message": "Invalid token"}), 401)

            if not current_user_permissions or not (
                current_user_permissions in permission
            ):
                return make_response(
                    {
                        "message": "Not authorized",
                    }
                )
            return f(*args, **kwargs)
        return decorator
    return deco

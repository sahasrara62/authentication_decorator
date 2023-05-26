from flask import Flask
from flask_migrate import Migrate
from flask_restful import Api

from library.views import app_route


def get_app(config="config.Config"):
    app = Flask(__name__)
    app.config.from_object(config)

    from library.models import db

    db.init_app(app)

    Api().init_app(app)
    Migrate().init_app(app, db)
    app.register_blueprint(app_route)
    return app

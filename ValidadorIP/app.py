from flask import Flask
from flask_restful import Api

from modelos.models import db
from views import IntrusionEventView

VALIDADOR_IP_PORT = 8002


def create_flask_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///validador_ip.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app_context = app.app_context()
    app_context.push()
    add_urls(app)
    return app


def add_urls(app):
    api = Api(app)
    api.add_resource(IntrusionEventView, "/intrusion-event")


app = create_flask_app()
db.init_app(app)
db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=VALIDADOR_IP_PORT, debug=True)

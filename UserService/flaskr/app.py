from flask import Flask
from flask_restful import Api
from flaskr.models.models import db
from flaskr.views.views import LoginView, LoginListView, UserView

app = None

def create_flask_app():
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user_service.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app_context = app.app_context()
    app_context.push()

    add_urls(app)

    return app


def add_urls(app):
    api = Api(app)

    api.add_resource(LoginView, "/login")
    api.add_resource(LoginListView, "/logins") # lista de logins de un usuario, se le pasa el id del usuario como query param, ej: /logins?user_id=1
    api.add_resource(UserView, "/users")

app = create_flask_app()

db.init_app(app)
db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=True)
from flask import Flask, jsonify, request
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

    api.add_resource(LoginView, "/login/<int:id_country_logged>")
    api.add_resource(LoginListView, "/logins") 
    api.add_resource(UserView, "/users")

app = create_flask_app()

@app.route("/intrusion-event", methods=["POST"])
def intrusion_event():
    data = request.get_json()
    print("RECIBIDO EN 8002:", data, flush=True)
    return jsonify({"ok": True, "data": data}), 200

db.init_app(app)
db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=True)
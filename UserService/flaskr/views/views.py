from flask import request
from flask_restful import Resource
from datetime import datetime, timezone
import requests

from flaskr.models.models import db, User, UserLogin, UserLoginSchema

class UserView(Resource):

    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {
                "status_code": 400,
                "message": "Username and password are required",
            }, 400

        user = User.query.filter_by(username=username).first()
        if user:
            return {
                "status_code": 400,
                "message": "Username already exists",
            }, 400

        new_user = User(username=username, password=password)

        try:
            db.session.add(new_user)
            db.session.commit()
            return {
                "status_code": 201,
                "message": "User created successfully",
                "user_id": new_user.id,
            }, 201
        except Exception:
            db.session.rollback()
            return {"status_code": 500, "message": "Error creating user"}, 500


class LoginView(Resource):

    def post(self):

        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {
                "status_code": 400,
                "message": "Username and password are required",
            }, 400

        # Mock de datos si no vienen
        ip_address = data.get("ip_address") or "181.45.23.10"
        location = data.get("location") or "Colombia"
        timestamp = datetime.now(timezone.utc)

        # Buscar o crear usuario
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()

        # Guardar login en base de datos
        new_login = UserLogin(
            user_id=user.id,
            ip_address=ip_address,
            location=location,
            timestamp=timestamp,
        )

        try:
            db.session.add(new_login)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return {"status_code": 500, "message": "Error saving login"}, 500

        # Crear evento para el detector

        login_event = {
            "user_id": username,
            "ip_address": ip_address,
            "location": location,
            "timestamp": timestamp.isoformat(),
        }

        # Enviar evento al IntrusionDetector
        try:
            requests.post(
                "http://localhost:5003/intrusion-event", json=login_event, timeout=5
            )
        except Exception:
            # No fallar si el detector aún no existe
            return {
                "status_code": 200,
                "message": "Login stored",
                "event": login_event,
            }, 200

        schema = UserLoginSchema()
        return {
            "status_code": 200,
            "message": "Login simulated successfully",
            "event": login_event,
            "login": schema.dump(new_login),
        }, 200


class LoginListView(Resource):
    ## Endpoint para obtener todos los logins (para pruebas)
    def get(self):
        logins = UserLogin.query.all()
        schema = UserLoginSchema(many=True)
        return {"status_code": 200, "logins": schema.dump(logins)}, 200

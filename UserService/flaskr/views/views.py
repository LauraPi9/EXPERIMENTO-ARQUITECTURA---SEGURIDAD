from sqlalchemy import select

from flask import request
from flask_restful import Resource
from datetime import datetime, timezone
import requests

from flaskr.models.models import db, User, UserLogin, UserLoginSchema, StatusUser


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

        new_user = User(username=username, password=password,status=StatusUser.ACTIVE.value)

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

    def put(self):
        data = request.get_json()
        user_id = data.get('user_id')
        new_status = data.get('status')
        search_user = db.session.get(User,user_id)

        if new_status == 'ACTIVE':
            search_user.status = StatusUser.ACTIVE.value
            db.session.commit()
            return {"message": "status has been changed to: " + new_status}, 200
        elif new_status == 'DEACTIVATED':
            search_user.status = StatusUser.DEACTIVATED.value
            db.session.commit()
            return {"message": "status has been changed to: " + new_status}, 200
        else:  
            db.session.rollback()
            return {"status_code": 500, "message": "Not a valid status: Only values allowed are: ACTIVE and DEACTIVATED"}, 500

class LoginView(Resource):
    ip_countries = [
        {"id_country": 1, "address_ip": "191.90.10.25", "country": "Colombia"},
        {"id_country": 2, "address_ip": "123.49.20.15", "country": "Bangladesh"},
        {"id_country": 3, "address_ip": "43.10.20.30", "country": "China"},
        {"id_country": 4, "address_ip": "163.90.25.14", "country": "Francia"},
        {"id_country": 5, "address_ip": "212.181.141.45", "country": "Suecia"}
    ]

    def login_to_dict(self,login):
        return {
            "id": login.id,
            "user_id": login.user_id,
            "status_user": str(login.user.status),
            "ip_address": login.ip_address,
            "location": login.location,
            "timestamp": str(login.timestamp),
        }

    def post(self, id_country_logged):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {
                "status_code": 400,
                "message": "Username and password are required",
            }, 400

        # Buscar usuario existente
        user = User.query.filter_by(username=username).first()
        if not user:
            return {
                "status_code": 404,
                "message": "User does not exist",
            }, 404

        # Verificar contraseña
        if user.password != password:
            return {
                "status_code": 401,
                "message": "Incorrect password",
            }, 401

        # Mock de datos si no vienen
        #ip_address = data.get("ip_address") or "181.45.23.10"

        ip_found = None
        for ip in self.ip_countries:
            if ip["id_country"] == id_country_logged:
                ip_found = ip

        #location = data.get("location") or "Colombia"
        timestamp = datetime.now(timezone.utc)

        # Guardar login en base de datos
        new_login = UserLogin(
            user_id=user.id,
            ip_address= ip_found["address_ip"],
            location=ip_found["country"],
            timestamp=timestamp,
        )

        try:
            db.session.add(new_login)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return {"status_code": 500, "message": "Error saving login"}, 500

        # Enviar evento al IntrusionDetector
        logins_totals = db.session.scalars(select(UserLogin).filter_by(user_id=user.id)).all()

        print(len(logins_totals))
        #print(logins_totals)
        start_index = len(logins_totals)

        if start_index < 10:
            start_index = 0
        else:
            start_index = len(logins_totals) -10
        
        loggins_answer = []

        for x in logins_totals[start_index:]:
            loggins_answer.append(self.login_to_dict(x))

        # Crear evento para el detector
        login_event = {
            "user_id": user.id,
            "username": user.username,
            "ip_address": ip_found["address_ip"],
            "location": ip_found["country"],
            "timestamp": timestamp.isoformat(),
            "loggins_list": loggins_answer
        }
        schema = UserLoginSchema()

        try:
            requests.post(
                "http://localhost:8002/intrusion-event", json=login_event, timeout=5
            )

        except Exception:
            # No fallar si el detector aún no existe
            print("fallo el servicio")
            return {
                "status_code": 400,
                "message": "Unable to save intrusion-event. This doesn't mean that the loggin event, wasn't saved.",
            }, 400

        return {
            "status_code": 200,
            "message": "Login simulated successfully",
            "event": login_event,
            "login": schema.dump(new_login),
        }, 200


class LoginListView(Resource):

    def get(self):
        logins = UserLogin.query.all()
        schema = UserLoginSchema(many=True)
        return {"status_code": 200, "logins": schema.dump(logins)}, 200

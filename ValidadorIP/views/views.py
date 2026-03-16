import time
from datetime import datetime, timezone
from dateutil import parser as date_parser

from flask import request
from flask_restful import Resource

import requests
from requests.exceptions import RequestException

from modelos.models import db, UserEvent


MINUTOS_UMBRAL_INTRUSION = 5

SEGUNDOS_UMBRAL_HIPOTESIS = 2.0


def _parse_timestamp(ts):

    if ts is None:
        return None
    if isinstance(ts, datetime):
        dt = ts
    elif isinstance(ts, str):
        dt = date_parser.parse(ts)
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def es_posible_intrusion(evento_actual, logins_list):
   
    if not logins_list or len(logins_list) < 2:
        return False

    ip_actual = evento_actual.get("ip_address") or ""
    location_actual = evento_actual.get("location") or ""
    ts_actual = _parse_timestamp(evento_actual.get("timestamp"))

    if not ts_actual:
        return False

    login_anterior = logins_list[-2]
    location_previo = (login_anterior.get("location") or "").strip()
    ip_previo = (login_anterior.get("ip_address") or "").strip()
    ts_previo = _parse_timestamp(login_anterior.get("timestamp"))

    if not ts_previo:
        return False

    misma_ubicacion = (
        location_actual.strip().lower() == location_previo.lower()
        and ip_actual.strip() == ip_previo
    )
    if misma_ubicacion:
        return False

    segundos_entre = abs((ts_actual - ts_previo).total_seconds())
    if segundos_entre <= MINUTOS_UMBRAL_INTRUSION * 60:
        return True
    return False


class IntrusionEventView(Resource):

    def post(self):
        t_inicio = time.perf_counter()
        data = request.get_json() or {}
        user_id = data.get("user_id")
        username = data.get("username")
        ip_address = data.get("ip_address", "")
        location = data.get("location", "")
        timestamp_str = data.get("timestamp")
        logins_list = data.get("loggins_list") or []

        if user_id is None:
            return {"status_code": 400, "message": "user_id is required"}, 400

        ts_dt = _parse_timestamp(timestamp_str)
        if not ts_dt:
            ts_dt = datetime.now(timezone.utc)
        evento_db = UserEvent(
            user_id=user_id,
            username=username or "",
            ip_address=ip_address,
            location=location,
            timestamp=ts_dt,
            logins_list=logins_list,
        )
        try:
            db.session.add(evento_db)
            db.session.commit()
        except Exception:
            db.session.rollback()

        if es_posible_intrusion(
            {
                "ip_address": ip_address,
                "location": location,
                "timestamp": timestamp_str,
            },
            logins_list,
        ):
            print(
                f"[INTRUSIÓN DETECTADA] user_id={user_id} username={username}: "
                f"inicio de sesión desde ubicación distinta en menos de {MINUTOS_UMBRAL_INTRUSION} minutos.",
                flush=True,
            )

            json_desactivar_usuario = {
                "user_id": user_id,
                "status": "DEACTIVATED",
            }

            try:
                res_desactivacion = requests.put(
                    "http://localhost:8082/users",
                    json=json_desactivar_usuario,
                    timeout=5
                )
                
                res_desactivacion.raise_for_status()

                print(res_desactivacion.json()["message"] or "Estado de usuario cambiado a: DESACTIVADO")
            except RequestException:
                return {
                    "status_code": 400,
                    "message": "Intrusión detectada, pero no se pudo notificar al servicio de Usuario."
                }, 400

        tiempo_segundos = time.perf_counter() - t_inicio
        cumple_hipotesis = tiempo_segundos < SEGUNDOS_UMBRAL_HIPOTESIS
        print(
            f"[EXPERIMENTO] Flujo de validación (recibir evento + persistir + detectar intrusión): "
            f"{tiempo_segundos:.4f} s — Hipótesis «detectar en <{SEGUNDOS_UMBRAL_HIPOTESIS}s»: {'SÍ CUMPLE' if cumple_hipotesis else 'NO CUMPLE'}",
            flush=True,
        )
        return {"status_code": 200, "message": "Event received", "ok": True}, 200

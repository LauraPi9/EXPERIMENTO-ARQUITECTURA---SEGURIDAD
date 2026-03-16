from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class UserEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    logins_list = db.Column(db.JSON, nullable=True)


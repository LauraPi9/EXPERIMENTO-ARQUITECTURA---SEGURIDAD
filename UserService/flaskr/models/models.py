import enum

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import fields

db = SQLAlchemy()

class StatusUser(enum.Enum):
    ACTIVE = "ACTIVE"
    DEACTIVATED = "DEACTIVATED"

class User (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    status = db.Column(db.Enum(StatusUser),nullable=True)
    
    logins = db.relationship(
        'UserLogin',
        back_populates='user',
        cascade='all, delete, delete-orphan'
    )

class UserLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable = False)
    location = db.Column(db.String(100), nullable = False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship('User', back_populates='logins')

# volver un objeto a json , serializarlo
class UserLoginSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = UserLogin
        load_instance = True
    timestamp = fields.DateTime()
    user = fields.Nested('UserSchema', exclude=('logins',))
    
    
class UserSchema(SQLAlchemyAutoSchema):
    user = fields.Enum(StatusUser, by_value=True, allow_none=True)

    class Meta:
        model = User
        load_instance = True
    logins = fields.Nested(UserLoginSchema, many=True, exclude=('user',)) ## 
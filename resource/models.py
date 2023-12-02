from sqlalchemy.dialects.postgresql import ARRAY
from resource import db
from datetime import datetime

likes = db.Table(
    "likes",
    db.Column("user.id", db.Integer, db.ForeignKey("user_sign_up.id"), primary_key=True),
    db.Column("dishview.id", db.Integer, db.ForeignKey("dishview.id"), primary_key=True)
)


class Users(db.Model):
    __tablename__ = "user_sign_up"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    firstname = db.Column(db.String(255), nullable=False, unique=False)
    lastname = db.Column(db.String(255), nullable=False, unique=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False, unique=False)
    phone = db.Column(db.String, nullable=True, unique=False)
    # one-to-many relationship with dishview
    dish_views = db.relationship('DishView', backref='creator', lazy=True)


class Dish(db.Model):
    __tablename__ = "dish"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(255), nullable=False, unique=False)
    Instructions = db.Column(db.String(500), nullable=False, unique=False)
    Ingredients = db.Column(ARRAY(db.String), nullable=False, unique=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # dish_views = db.relationship('DishView', backref='dish', lazy=True)


class DishView(db.Model):
    __tablename__ = "dishview"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(255), nullable=False, unique=False)
    Instructions = db.Column(db.String(500), nullable=False, unique=False)
    Ingredients = db.Column(ARRAY(db.String), nullable=False, unique=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    dish_image_url = db.Column(db.LargeBinary, nullable=True, default='default.jpg')
    # many-to-many relationship-----many users can like many dishes
    user_likes = db.relationship("Users", secondary="likes", backref="liked_dishes", lazy="dynamic")
    # one-to-many relationship----many dish can be created by one user
    user_id = db.Column(db.Integer, db.ForeignKey('user_sign_up.id'))


class UserLogin(db.Model):
    __tablename__ = "user_login"
    __table_args__ = {"extend_existing": True}

    email = db.Column(db.String(255), nullable=False, unique=False, primary_key=True)
    password = db.Column(db.String(255), nullable=False, unique=False)


class RevokeToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

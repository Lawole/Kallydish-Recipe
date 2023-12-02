from flask import Flask
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:password@localhost:5433/kally"
app.config["SECRET_KEY"] = "EGGRO11$$123"
db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)


from resource import models

api = Api(app, version="1.0", title="KallyDish", description="API for your KallyDish")

from resource.routes import user, dish


api.add_namespace(user)
api.add_namespace(dish)


# api.add_resource(Hello, '/home')
# api.add_resource(Swagger, '/swagger')
# api.add_resource(Restaurant, '/restaurant')


with app.app_context():
    db.create_all()

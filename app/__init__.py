from flask import Flask,redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    
    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return redirect(url_for('main.login', message="Please log in to access this page"))

    from app.routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    return app

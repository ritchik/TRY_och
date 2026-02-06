from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

import redis
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


 
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

def create_app():
    app = Flask(__name__)

     
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', '${SECRET_KEY}'),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            'DATABASE_URL',
            'postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/flask_notes?client_encoding=utf8'
        ),
        REDIS_URL=os.getenv('REDIS_URL', 'redis://redis:6379/0'),
        PREFERRED_URL_SCHEME='https',
        PROPAGATE_EXCEPTIONS=True,
        DEBUG=os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
         

        WTF_CSRF_ENABLED=False
    )

     
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)


     
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'

     
    redis_instance = redis.StrictRedis.from_url(app.config['REDIS_URL'])
    app.extensions['redis'] = redis_instance

     
    limiter.storage_backend = redis_instance
    limiter.init_app(app)
    limiter.default_limits = ["200 per day", "50 per hour"]


    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
         
    from app.routes import main
    app.register_blueprint(main)

    return app
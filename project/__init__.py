from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

# Load environment variables
load_dotenv()
env = os.environ

db = SQLAlchemy()
secret_key = os.urandom(32)
limiter = Limiter(get_remote_address)

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secret_key
    app.config['WTF_CSRF_SECRET_KEY'] = secret_key
    
    # Use PostgreSQL in production, SQLite in development
    if os.environ.get('FLASK_ENV') == 'production':
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login_get"
    login_manager.init_app(app)

    limiter.init_app(app)

    # Add security headers
    Talisman(app, 
        force_https=True,
        content_security_policy=None,  # Temporarily disable CSP
        session_cookie_secure=True,
        session_cookie_http_only=True
    )

    csrf = CSRFProtect()
    csrf.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(uid):
        return User.query.get(int(uid))

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    with app.app_context():
        db.create_all()
        # Initialize admin user within the app context
        from .auth import init_admin
        init_admin()

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    return app

# Add this at the bottom of the file
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

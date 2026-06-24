from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import logging

# Initialize SQLAlchemy and LoginManager extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    
    # Initialize extension instances
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'danger'
    
    # User loader callback for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
        
    with app.app_context():
        # Register routes and models
        from app.routes import auth_bp
        from app.admin import admin_bp
        
        app.register_blueprint(auth_bp)
        app.register_blueprint(admin_bp)
        
        # Initialize tables
        db.create_all()
        
        # Seed default roles, initial keys, and an admin user
        from app.auth import seed_database
        try:
            seed_database()
            app.logger.info("Database seeding and cryptographic initialization successful.")
        except Exception as e:
            app.logger.error(f"Error during startup seeding/crypto setup: {str(e)}")
            
    return app

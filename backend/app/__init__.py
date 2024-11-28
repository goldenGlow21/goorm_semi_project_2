from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'

    CORS(app)

    # Register routes
    from .routes import bp
    app.register_blueprint(bp)

    return app
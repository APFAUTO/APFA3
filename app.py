
"""
POR Upload Application
A Flask-based system for processing Purchase Order Requests (POR) from Excel files.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask

# Setup logging
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

# File handler
file_handler = RotatingFileHandler('logs.txt', maxBytes=10240, backupCount=10)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.ERROR)

# Get root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def create_app():
    # Flask app setup
    app = Flask(__name__)
    app.config.update(
        UPLOAD_FOLDER="static/uploads",
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
        SECRET_KEY=os.environ.get('SECRET_KEY', 'a-very-secret-key')
    )

    # Add cache-busting headers to all responses
    @app.after_request
    def add_cache_headers(response):
        """Add cache-busting headers to prevent browser caching."""
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    from routes import routes
    app.register_blueprint(routes)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)

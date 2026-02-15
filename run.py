#!/usr/bin/env python3
"""Storage Dashboard - Main application entry point"""
import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Only enable debug mode in development
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=5000, debug=debug)

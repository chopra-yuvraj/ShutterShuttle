"""Initialize database on Render deployment"""
import os
from server import app, db, init_database

if __name__ == '__main__':
    with app.app_context():
        try:
            init_database()
            print("✅ Database initialized successfully")
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            raise

# reset_db.py
from app import app, db

with app.app_context():
    print("Dropping old tables...")
    db.drop_all()  # This deletes the table with the "too short" column
    print("Creating new tables...")
    db.create_all() # This creates the new table with String(255)
    print("Done! Database reset.")
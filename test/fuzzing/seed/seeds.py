import os
import time
import uuid
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.sql import func
from sqlalchemy.exc import OperationalError

# 1. Setup Database Connection with Retry Logic
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/mydatabase")

def get_engine():
    retries = 5
    while retries > 0:
        try:
            engine = create_engine(DATABASE_URL)
            connection = engine.connect()
            connection.close()
            print("Successfully connected to the database!")
            return engine
        except OperationalError:
            print("Database not ready yet. Retrying in 2 seconds...")
            time.sleep(2)
            retries -= 1
    raise Exception("Could not connect to the database after multiple retries.")

engine = get_engine()
Base = declarative_base()

# 2. Define the Models
class User(Base):
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String(255), unique=True, nullable=False)
    role = Column(String(255), nullable=False, default='user')
    uid_number = Column(Integer, unique=True)
    student_id = Column(String(50), unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    settings = relationship("Setting", back_populates="user", uselist=False, cascade="all, delete-orphan")

class Setting(Base):
    __tablename__ = 'settings'

    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True)
    full_name = Column(String(255))
    linux_username = Column(String(255))
    user = relationship("User", back_populates="settings")

# 3. Create Extension and Tables
# We must create pgcrypto first so gen_random_uuid() works in table definitions
with engine.connect() as conn:
    conn.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto";'))
    conn.commit()

Base.metadata.create_all(engine)

# 4. Prepare Data
users_data = [
    {
        "id": uuid.UUID('6755aa20-0752-4c0a-9a09-8bcfe8d225da'),
        "email": 'testuser@example.com',
        "role": 'user',
        "uid_number": 20001,
        "student_id": 'S12345678',
        "settings": {"full_name": 'Test User', "linux_username": 'testuser'}
    },
    {
        "id": uuid.UUID('474410d9-5eb9-4359-a469-4e5c7366f9ee'),
        "email": 'testadmin@example.com',
        "role": 'admin',
        "uid_number": 20003,
        "student_id": 'S12345680',
        "settings": {"full_name": 'Test Admin', "linux_username": 'testadmin'}
    },
    {
        "id": uuid.UUID('4336d85b-9a5f-486c-a7a8-075dc4f84da3'),
        "email": 'testorganizer@example.com',
        "role": 'organizer',
        "uid_number": 20004,
        "student_id": 'S12345681',
        "settings": {"full_name": 'Test Organizer', "linux_username": 'testorganizer'}
    }
]

# 5. Insert Data
Session = sessionmaker(bind=engine)
session = Session()

try:
    # Check if data exists to avoid duplicates on re-runs
    if session.query(User).first():
        print("Data already exists. Skipping insertion.")
    else:
        for data in users_data:
            settings_info = data.pop("settings")
            new_user = User(**data)
            new_settings = Setting(
                user=new_user,
                full_name=settings_info['full_name'],
                linux_username=settings_info['linux_username']
            )
            session.add(new_user)
            session.add(new_settings)

        session.commit()
        print("Data populated successfully.")

except Exception as e:
    session.rollback()
    print(f"An error occurred: {e}")

finally:
    session.close()
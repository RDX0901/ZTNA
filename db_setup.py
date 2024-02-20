from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import random

# Step 1: Create an SQLite database engine
db_url = "sqlite:///mydatabase.db"
engine = create_engine(db_url)

# Step 2: Create a session
Session = sessionmaker(bind=engine)
db_session = Session()

# Step 3: Define a base class for declarative models
Base = declarative_base()

# Step 4: Define a model class
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)  # Specify 'id' as the primary key
    username = Column(String)
    password = Column(String)
    otp = Column(String)
    role = Column(String)
    flag = Column(String)
    resources = Column(String)  # Store resources as a comma-separated string

# Step 5: Create tables in the database
Base.metadata.create_all(engine)

# Step 6: Insert data

# Check if the user with the provided username already exists
existing_user = db_session.query(User).filter_by(username='adim@example.com').first()
print(existing_user)

if existing_user is None:
    # If the user does not exist, add the new user
    new_user = User(username='admin@example.com', password='admin@1234', otp=str(random.randint(100000, 999999)), role='user', flag='inactive', resources='')
    
    if new_user.username == 'admin@example.com':
        new_user.role = 'admin'
    
    db_session.add(new_user)
else:
    if existing_user.username == 'admin@example.com':
        # Update the admin user's OTP
        existing_user.otp = str(random.randint(100000, 999999))
        db_session.commit()
        print("Admin user's OTP updated")
    else:
        existing_user.otp = str(random.randint(100000, 999999))
        print(existing_user.otp)
        db_session.commit()
        print("User already exists")

# Step 7: Query and print data
users = db_session.query(User).all()
# for user in users:
#     print(f"User ID: {user.id}, Username: {user.username}, Role: {user.role}, OTP: {user.otp}, Flag: {user.flag}, Resources: {user.resources}")

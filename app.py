from flask import Flask, render_template, request, redirect, url_for, session
import os
import smtplib
import random
import threading
import secrets
from flask_socketio import SocketIO, send
import eventlet
from sqlalchemy.exc import IntegrityError
from db_setup import users, User, db_session

eventlet.monkey_patch()

active_sessions = {}

def user_dictionaries_func(users):
    users_dictionaries = []
    for user in users:
        user_dict = {
            "userid": user.id,
            "username": user.username,
            "password": user.password,
            "otp": user.otp,
            "role": user.role,
            "flag": user.flag,
            "resources": user.resources,
        }
        users_dictionaries.append(user_dict)
    return users_dictionaries

users_dictionaries = user_dictionaries_func(users=users)

app = Flask(__name__, static_url_path='/static')
app.secret_key = os.urandom(24)
app.config['STATIC_FOLDER'] = 'static'
app.config['SECRET_KEY'] = '12345'
socketio = SocketIO(app, cors_allowed_origins='*')

# Create a lock to ensure thread safety during database operations
db_lock = threading.Lock()
db_lock2 = threading.Lock()


@app.route('/')
def home():
    if 'username' in session:
        return 'You are logged in as ' + session['username']
    return render_template('welcome_page.html')

def generate_session_id(length=32):
    session_id = secrets.token_hex(length)
    return session_id

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = db_session.query(User).all()
        users_dictionaries = user_dictionaries_func(users=users)
        for every_user_dict in users_dictionaries:
            if every_user_dict['username'] == username and every_user_dict['password'] == password:
                otp = every_user_dict['otp']
                send_otp_email(username, otp)
                start_session(username, session_id=generate_session_id())
                session['role'] = every_user_dict['role']
                session['username'] = username
                session['resources'] = every_user_dict['resources']
                return render_template('verify_otp.html')
        else:
            return 'Invalid credentials. Please try again.'
    return render_template('login.html')

@app.route('/verify', methods=['POST'])
def verify_otp():
    entered_otp = request.form['entered_otp']
    with db_lock:
        users = db_session.query(User).all()
        users_dictionaries = user_dictionaries_func(users=users)

    for every_user_dict in users_dictionaries:
        if every_user_dict['username'] == session['username'] and every_user_dict['password']:
            otp = every_user_dict['otp']
            resources = every_user_dict['resources']
            expected_otp = otp
            if entered_otp == expected_otp:
                session.pop('otp', None)
                if every_user_dict['role'] == 'admin':
                    with db_lock:
                        users = db_session.query(User).all()
                        users_dictionaries = user_dictionaries_func(users=users)
                    return render_template('admin_dashboard.html', username=every_user_dict['username'], users=users_dictionaries)
                else:
                    return render_template('user_dashboard.html', username=every_user_dict['username'], resources=resources)
            else:
                return 'Invalid OTP. Please try again.'

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        for keys, values in active_sessions.items():
            if username in values['username']:
                del active_sessions[keys]
            session.pop('username', None)
            session.pop('session_id', None)
            return "Logged out successfully."
        else:
            return "User not logged in."
    return redirect(url_for('home'))

def send_otp_email(email, otp):
    sender_email = 'no.reply@example.com' # Enter your email for SMTP server
    sender_app_password = 'password' # enter your SMTP password
    subject = 'Verification Code for MFA'
    body = f'Your verification code is: {otp}'

    # Compose the email message
    message = f'Subject: {subject}\n\n{body}'
    print(otp)

    try:
        # Connect to the Yahoo Mail SMTP server using SSL/TLS
        server = smtplib.SMTP_SSL('smtp.mail.yahoo.com', 465) # Setup for Yahoo , cahnge as your requirement

        # Login to the Yahoo Mail account with the app password
        server.login(sender_email, sender_app_password)

        # Send the email
        server.sendmail(sender_email, email, message)
        print('Verification email sent successfully.')

        # Close the connection
        server.quit()

        # Return the verification code
        return otp
    except smtplib.SMTPAuthenticationError as e:
        print('Failed to authenticate. Make sure your Yahoo app password is correct.')
        return None
    except smtplib.SMTPException as e:
        print('Failed to send the verification email:', e)
        return None
import logging


@app.route('/admin_dashboard')
def admin_dashboard():
    target_username = request.args.get('user', 'Unknown User')
    
    try:
        # Acquire the lock before performing database operations
        # with db_lock:
        users = db_session.query(User).all()
        print("ss",users)
        users_dictionaries = user_dictionaries_func(users=users)

        return render_template('admin_dashboard.html', username=session['username'], users=users_dictionaries, target_username=target_username)
    except Exception as e:
        # Log the exception details to a file or console
        logging.error(f"Exception in admin_dashboard: {str(e)}")
        # Handle the exception gracefully
        # with db_lock:
        try:
            users = db_session.query(User).all()

            users_dictionaries = user_dictionaries_func(users=users)
            print('m')
            db_session.rollback()

            return render_template('admin_dashboard.html', username=session['username'], users=users_dictionaries, target_username=target_username)

        except Exception as inner_e:
            logging.error(f"Exception during rollback: {str(inner_e)}")
            users = db_session.query(User).all()

            users_dictionaries = user_dictionaries_func(users=users)

            return render_template('admin_dashboard.html', username=session['username'], users=users_dictionaries, target_username=target_username)

@app.route('/user_management')
def user_management_dashboard():
    print(len(active_sessions))
    return render_template('user_management.html', username=session['username'], active_sessions=active_sessions)

def start_session(username, session_id):
    active_sessions[session_id] = {'username': username}
    print(active_sessions)
    return active_sessions

@app.route('/admin_chat')
def admin_chat():
    target_username = request.args.get('user', 'Unknown User')
    print(target_username)
    return render_template('admin_chat.html', username=session['username'], target_username=target_username, active_sessions=active_sessions)

@app.route('/user_chat')
def user_chat():
    target_username = request.args.get('user', 'Unknown User')
    return render_template('user_chat.html', username=session['username'], target_username=target_username)

@socketio.on('message')
def handle_message(message):
    if message != 'User connected!':
        send(message, broadcast=True)

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' not in session:
        return redirect(url_for('home'))

    if session['role'] != 'admin':
        return 'You do not have permission to access this page.'

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        secret_key = request.form['secret_key']
        selected_resources = request.form.getlist('resources[]')

        if secret_key == app.config['SECRET_KEY']:
            user = User(username=username, password=password, otp=str(random.randint(100000, 999999)), role='admin', flag='inactive', resources=','.join(selected_resources))
        else:
            user = User(username=username, password=password, otp=str(random.randint(100000, 999999)), role='user', flag='inactive', resources=','.join(selected_resources))

        try:
            with db_lock:
                existing_user = db_session.query(User).filter_by(username=username).first()

                if existing_user:
                    return 'User already exists. Please choose a different username.'

                db_session.add(user)
                db_session.commit()
                db_session.close()

            
            return f'{user} Registration successful!'
        except RuntimeError:
            db_session.rollback()
            return f'{user} Registration successful!'
        except Exception as e:
            return f"Exception while creating user/admin: {e}"
    return render_template('register.html')

@app.route('/resource1')
def resource_1():
    if 'Resource 1' not in session['resources']:
        return 'You do not have permission to access this page.'
    return render_template('resource_1.html')

@app.route('/resource2')
def resource_2():
    if '2' not in session['resources']:
        return 'You do not have permission to access this page.'
    return render_template('resource_2.html')

@app.route('/resource3')
def resource_3():
    if '3' not in session['resources']:
        return 'You do not have permission to access this page.'
    return render_template('resource_3.html')

@app.route('/remove_user/<username>', methods=['GET'])
def remove_user(username):
    if 'username' not in session:
        return redirect(url_for('home'))

    if session['role'] != 'admin':
        return 'You do not have permission to remove users.'

    try:
        user_to_remove_db = db_session.query(User).filter_by(username=username).first()
        if user_to_remove_db:
            with db_lock:
                db_session.delete(user_to_remove_db)
                users = db_session.query(User).all()
                users_dictionaries = user_dictionaries_func(users=users) 
                return render_template('admin_dashboard.html', username=session['username'], users=users_dictionaries)
        else:

            # return f'User {username} not found in the database.'
            users = db_session.query(User).all()
            users_dictionaries = user_dictionaries_func(users=users)

            return render_template('admin_dashboard.html', username=session['username'], users=users_dictionaries)
        
    except Exception as e:
        db_session.rollback()
        users = db_session.query(User).all()
        users_dictionaries = user_dictionaries_func(users=users)

        return render_template('admin_dashboard.html', username=session['username'], users=users_dictionaries)

        # return f'Error removing user: {str(e)}'

@app.route('/user_deletion')
def user_deletion():
    try:
        with db_lock:
            users = db_session.query(User).all()
            users_dictionaries = user_dictionaries_func(users=users)
            return render_template('user_deletion.html', users_dictionaries=users_dictionaries)
    except RuntimeError:
            db_session.rollback()
            users = db_session.query(User).all()
            users_dictionaries = user_dictionaries_func(users=users)
            return render_template('user_deletion.html', users_dictionaries=users_dictionaries)
    
if __name__ == '__main__':
    socketio.run(app, debug=True)

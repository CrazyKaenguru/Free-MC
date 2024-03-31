from flask import Flask, render_template, request, redirect, session
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.hash import sha256_crypt
from sqlalchemy import DateTime
from datetime import datetime
from flask_socketio import SocketIO
import subprocess
from threading import Thread
import os
from shutil import copytree
import psutil
app = Flask(__name__)
socketio = SocketIO(app)
import json
app.secret_key = "your_secret_key"

Base = declarative_base()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
minecraft_process = None
minecraft_processes = []
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    servers = relationship("MinecraftServer", back_populates="owner")

class MinecraftServer(Base):
    __tablename__ = 'minecraft_servers'
    id = Column(Integer, primary_key=True)
    server_id = Column(String, unique=True)
    owner_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship("User", back_populates="servers")
    process_id = Column(String)  # Add process_id columnw

user_engine = create_engine('sqlite:///users_database.db', pool_pre_ping=True)
minecraft_engine = create_engine('sqlite:///minecraft_database.db', pool_pre_ping=True)


Base.metadata.create_all(user_engine)
Base.metadata.create_all(minecraft_engine)

UserSession = sessionmaker(bind=user_engine)
user_db_session = UserSession()

MinecraftServerSession = sessionmaker(bind=minecraft_engine)
minecraft_db_session = MinecraftServerSession()

@app.route('/')
def home():
    if 'username' in session:
        user = user_db_session.query(User).filter_by(username=session['username']).first()
        if user:
            servers = user.servers
            return render_template('servers.html', servers=servers, username=user.username)
        else:
            return 'User not found'
    else:
        return render_template('login.html')

@app.route('/server', methods=['GET', 'POST'])
def server():
    if request.method == 'GET':
        server_id_value = request.args.get('server_id')
        user = user_db_session.query(User).filter_by(username=session['username']).first()
        if(user_db_session.query(MinecraftServer).filter_by(server_id=server_id_value, owner=user).first()):
            return render_template('server.html', username=session['username'], server_id=server_id_value)
    return render_template('login.html')

from flask import render_template

@app.route('/start-server', methods=['GET'])
def start_server():
    server_id = request.args.get('id')
    ram_amount = 2048  # Example RAM amount
    Thread(target=start_minecraft_server, args=(server_id, ram_amount)).start()
    return render_template('server.html',server_id=server_id)
@app.route('/stopp-server', methods=['GET'])
def stopp_server():
    server_id = request.args.get('id')
    existing_process = get_minecraft_process(server_id)
    if existing_process:
        write_to_server_console(existing_process, "stop \n")
    
    return redirect("/")

from flask_socketio import SocketIO, emit

from flask import Flask, Response

from flask_socketio import emit
from flask import request
from flask_socketio import emit

import threading

import threading
import subprocess
import os

def start_minecraft_server(server_id, ram_amount):
    print("starting server")
    #server_directory = r"C:\Users\Quirin\Documents\GitHub\Free-MC\MC_Servers\\" + server_id 
    server_directory = os.path.join(BASE_DIR, 'MC_Servers', server_id)
    os.chdir(server_directory)
    
    ram_argument = f"-Xmx{ram_amount}M -Xms{ram_amount}M"

    minecraft_process = subprocess.Popen(["java", "-Xmx1024M", "-Xms1024M", "-jar", "paper.jar", "nogui"], 
                                         cwd=server_directory, 
                                         stdin=subprocess.PIPE, 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, 
                                         creationflags=subprocess.CREATE_NO_WINDOW)
    
    # Append the subprocess object to the list
    minecraft_processes.append(minecraft_process)
    
    server = user_db_session.query(MinecraftServer).filter_by(server_id=server_id).first()
    if server:
        # Update the process_id attribute of the MinecraftServer object
        server.process_id = str(minecraft_process.pid)  # Assuming pid gives the process ID as an integer
        user_db_session.commit()

        # Function to read and emit log output in real-time
        def emit_log_messages():
            while True:
                # Read and emit stdout
                stdout_line = minecraft_process.stdout.readline().decode().strip()
                if not stdout_line:
                    break  # Exit loop if there is no more output
                socketio.emit('log_message_'+server_id, stdout_line)  # Emit log message to clients

            # Read and emit stderr
            while True:
                stderr_line = minecraft_process.stderr.readline().decode().strip()
                if not stderr_line:
                    break  # Exit loop if there is no more output
                socketio.emit('log_message_'+server_id, stderr_line)  # Emit log message to clients
        
        # Start a separate thread to emit log messages
        log_thread = threading.Thread(target=emit_log_messages)
        log_thread.start()
    else:
        print("No server found!")

        
    

        
    



def get_minecraft_process(server_id):
    for process in minecraft_processes:
        for server in user_db_session.query(MinecraftServer).filter_by(server_id=server_id).all():
            print(server.process_id)
            if process.poll() is None and process.pid == int(server.process_id):
                return process
    return None

from flask import Flask, request, send_file
import time
@app.route('/get-latest-log')
def get_latest_log():
    # Get the server ID from the request parameters
    server_id = request.args.get('server_id')

    return render_template("server.html",server_id=server_id)

@app.route('/test')
def test():
    server_id = request.args.get('id')
    existing_process = get_minecraft_process(server_id)
    if existing_process:
        write_to_server_console(existing_process, "stop \n")
    else :
        print("no right existing process found")
    return redirect("/")

@app.route('/sendcommand', methods=['GET'])
def sendcommand():
    print("received")#
    for process in minecraft_processes:
       print(process)
    server_id = request.args.get('id')
    message=request.args.get('message')
    existing_process = get_minecraft_process(server_id)
    if existing_process:
        if message is not None:
             write_to_server_console(existing_process, message + "\n")
    else:
        print("no existing process")
    return redirect("/")
    
# Function to write to the stdin of a subprocess
def write_to_server_console(process, message):
    print("Trying to write")
    if process is not None:
        print(process)
        process.stdin.write(message.encode())
        process.stdin.flush()
    else:
        print("Process not found")
        

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_db_session.query(User).filter_by(username=username).first()
        if user and sha256_crypt.verify(password, user.password):
            session['username'] = username
            return redirect('/')
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = sha256_crypt.hash(request.form['password'])
        if user_db_session.query(User).filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        if user_db_session.query(User).filter_by(email=email).first():
            return render_template('register.html', error='Email already exists')
        user = User(username=username, email=email, password=password, created_at=datetime.utcnow())
        user_db_session.add(user)
        user_db_session.commit()
        session['username'] = username  # Automatically log in after registration
        return redirect('/')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/create_server', methods=['GET', 'POST'])
def create_server():
    if 'username' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        try:
            user = user_db_session.query(User).filter_by(username=session['username']).first()
            server_id = request.form['server_id']
            
            if minecraft_db_session.query(MinecraftServer).filter_by(server_id=server_id).first():
                return render_template('create_server.html', error='Server ID already exists')
            
            # Corrected path for copying server directory
            new_server_dir = './MC_Servers/' + server_id
            copytree('./MC_Servers/example', new_server_dir)
            
            # Removed process_id=None from MinecraftServer instantiation
            server = MinecraftServer(server_id=server_id, owner=user)
            user_db_session.add(server)  # Add the server to the same session as the user
            user_db_session.commit()  # Commit changes
            
            return redirect('/')
        except SQLAlchemyError as e:
            print(e)  # Print the SQLAlchemy error
            user_db_session.rollback()  # Rollback changes in case of error
            return render_template('create_server.html', error='An error occurred while creating the server')
    
    return render_template('create_server.html')

if __name__ == '__main__':
    app.run(debug=False)

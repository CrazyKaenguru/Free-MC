import os
from shutil import copytree
from flask import Flask, render_template, request, redirect, session
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.hash import sha256_crypt
from sqlalchemy import DateTime
from datetime import datetime
import traceback
from sqlalchemy.exc import SQLAlchemyError
from flask_socketio import SocketIO
import subprocess
from threading import Thread
import os

# Get the current directory
current_directory = os.getcwd()
app = Flask(__name__)
socketio = SocketIO(app)

app = Flask(__name__)
app.secret_key = "your_secret_key"

Base = declarative_base()

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

# Replace 'sqlite:///users_database.db' and 'sqlite:///minecraft_database.db' with your desired database URIs
user_engine = create_engine('sqlite:///users_database.db', echo=True)
minecraft_engine = create_engine('sqlite:///minecraft_database.db', echo=True)

# Create the users database
Base.metadata.create_all(user_engine)

# Create the Minecraft servers database
Base.metadata.create_all(minecraft_engine)

# Create the user database session
UserSession = sessionmaker(bind=user_engine)
user_db_session = UserSession()

# Create the Minecraft server database session
MinecraftServerSession = sessionmaker(bind=minecraft_engine)
minecraft_db_session = MinecraftServerSession()

@app.route('/')
def home():
    if 'username' in session:
        # Get the user from the database
        user = user_db_session.query(User).filter_by(username=session['username']).first()
        if user:
            # Get all servers owned by the user
            servers = user.servers
            return render_template('servers.html', servers=servers,username=user.username)
        else:
            return 'User not found'
    else:
        return redirect(url_for('login'))

@app.route('/server', methods=['GET', 'POST'])
def server():
    if request.method =='GET':
        server_id_value = request.args.get('server_id')
       
        user = user_db_session.query(User).filter_by(username=session['username']).first()
      
        if(user_db_session.query(MinecraftServer).filter_by(server_id=server_id_value, owner=user).first()):
            return render_template('server.html',username=session['username'],server_id=server_id_value)
    return render_template('login.html')    

@app.route('/start-server', methods=['POST'])
def start_server():
    Thread(target=start_minecraft_server).start()
    return 'Minecraft server starting...'



def start_minecraft_server():
  # Specify the path to the Minecraft server jar file relative to the current directory
    minecraft_server_path = os.path.join(current_directory, 'MC_Servers',"3","Minecraft_Server_Test", 'paper.jar')

# Start the Minecraft server using the full path
def run_batch_file(batch_file_path):
    batch_dir = os.path.dirname(r'C:\Users\Quirin\Documents\GitHub\Free-MC\MC_Servers\3\Minecraft_Server_Test\run.bat')
    os.chdir(batch_dir)
    # Open the batch file and capture its output
    with subprocess.Popen(batch_file_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True) as process:
            # Read and print each line of output
            for line in process.stdout:
                print(line.strip())  # Print the line (remove trailing newline)
        
run_batch_file(r'C:\Users\Quirin\Documents\GitHub\Free-MC\MC_Servers\3\Minecraft_Server_Test\run.bat')
print("++++++++++++++++++++mc_serverstarted")
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
            
            # Copy the example Minecraft server directory to create a new server
            new_server_dir = './MC_Servers/'+server_id
            copytree('./MC_Servers/example', new_server_dir)
            
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
    app.run(debug=True)

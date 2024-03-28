from flask import Flask, render_template, request, redirect, session
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.hash import sha256_crypt
from sqlalchemy import DateTime
from datetime import datetime, timedelta, timezone
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

# Replace 'sqlite:///database.db' with your database URI
engine = create_engine('sqlite:///database.db', echo=True)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db_session = Session()

@app.route('/')
def home():
    if 'username' in session:
        return f'Hello, {session["username"]}! <a href="/logout">Logout</a>'
    else:
        return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db_session.query(User).filter_by(username=username).first()
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
        if db_session.query(User).filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        if db_session.query(User).filter_by(email=email).first():
            return render_template('register.html', error='Email already exists')
        user = User(username=username, email=email, password=password, created_at=datetime.utcnow())
        db_session.add(user)
        db_session.commit()
        session['username'] = username  # Automatically log in after registration
        return redirect('/')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)

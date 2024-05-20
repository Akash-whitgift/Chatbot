from gevent import monkey
monkey.patch_all()
from flask_compress import Compress
from flask import Flask, render_template, request, jsonify, flash, redirect, session
import openai
import os
my_secret = os.environ['API']
import time
import bcrypt
import csv
from gevent.pywsgi import WSGIServer
import configparser
import random
import psycopg2
import datetime
conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
)
import datetime
key = str(random.randrange(16**32))

gpt3 = 'gpt-3.5-turbo-16k'
gpt4 = 'gpt-4-1106-preview'
CONFIG_FILE = 'config.ini'

app = Flask(__name__)
app.secret_key = key
# Set up OpenAI API
openai.api_key = my_secret
@app.route('/img')
def img():
  return 
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/', methods=['POST'])

@app.route('/generate', methods=['POST'])
def generate():
    seconds = time.time()
    creation = time.ctime(seconds)
    user_input = request.form['input']
    username = session['username']
    if len(user_input) < 1 :
      return redirect('/dashboard')
    conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    
    response = openai.ChatCompletion.create(
        model='gpt-4o',  # Specify the model
        messages=[{"role": "system", "content": "You are a informative helpful chatbot, but can be a bit funny."},
                  {"role": "user", "content": user_input}]
    )
      
    generated_text = response.choices[0].message['content']
    cur.execute("""
    INSERT INTO chats (username, time, message, query) VALUES (%s, %s, %s, %s)
    """, (username, datetime.datetime.now(),generated_text, user_input))
    conn.commit()
    return jsonify({'generatedText': generated_text})


#Not AI related

def is_admin(username):
    with open("database.csv", 'r') as db:
        data = [line.strip().split(',') for line in db]

        for record in data:
            if record[0] == username:
                return record[2] == 'True'

        return False

@app.route('/login', methods=['POST'])
def user_login():
  username = request.form['username']
  password = request.form['password']

  # Regular login for all users
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT hashed_password, salt, admin_status FROM users WHERE username = %s", (username,))
  result = cur.fetchone()


  if result is None:
    flash('Invalid username', 'error')
    return redirect('/')

  hashed_password, salt, is_admin = result


  if bcrypt.checkpw(password.encode(), hashed_password.encode()):
    session['username'] = username
    session['is_admin'] = is_admin
    cur.execute('UPDATE users SET last_login = %s WHERE username = %s', (datetime.datetime.utcnow(), username))
    conn.commit()
    print(datetime.datetime.utcnow())
    cur.close()
    flash('Login successful', 'success')
    return redirect('/dashboard')
  else:
    flash('Invalid password', 'error')
    return redirect('/')

  return redirect('/')

def check_credentials(username, password):
    with open("database.csv", 'r') as db:
        data = [line.strip().split(',') for line in db]

    with open("salts.csv", 'r') as salts_file:
        salts_data = [line.strip().split(',') for line in salts_file]

    users = {record[0]: (record[1], None) for record in data}
    salts = {record[0]: record[1] for record in salts_data}

    if username in users and username in salts:
        hashed_password, salt = users[username][0].encode('utf-8'), salts[username].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), salt + hashed_password):
            session['username'] = username
            session['is_admin'] = users[username][2] == 'True'
            return session['is_admin']

    flash("Username or password incorrect")
    return False

def get_admin_only_mode():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'AppConfig' in config and 'admin_only_mode' in config['AppConfig']:
        return config.getboolean('AppConfig', 'admin_only_mode')
    return False

@app.route('/signout', methods=['POST'])
def sign_out():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
  if get_admin_only_mode():
    flash('Registration is currently unavailable', 'error')
    return redirect('/')

  if request.method == 'GET':
    return render_template('register.html')

  username = request.form['username']
  password = request.form['password']
  confirm_password = request.form['confirm_password']

  if password != confirm_password:
    flash('Passwords do not match', 'error')
    return redirect('/register')

  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT username FROM users WHERE username = %s", (username,))
  existing_usernames = [item[0] for item in cur.fetchall()]

  if username in existing_usernames:
    flash('Username already exists', 'error')
    return redirect('/register')
  if username[0] == '_':
    flash('Cannot start with an underscore', 'error')
    return redirect('/register')
  if len(password) < 6:
    flash('Password too short', 'error')
    return redirect('/register')

  salt = bcrypt.gensalt().decode()
  hashed_password = bcrypt.hashpw(password.encode(), salt.encode()).decode()

  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute(
    "INSERT INTO users (username, hashed_password, salt, admin_status, account_created) VALUES (%s, %s, %s, %s, %s)",
    (username, hashed_password, salt, False, datetime.datetime.utcnow())
  )
  cur.execute('UPDATE users SET last_login = %s WHERE username = %s', (datetime.datetime.utcnow(), username))
  conn.commit()
  session['username'] = username
  flash('Registration successful', 'success')
  return redirect('/')

@app.route('/dashboard')
def dashboard():
  if 'username' not in session:
    return redirect('/')
  return render_template('index.html')


if __name__ == "__main__":
    Compress(app)
    http_server = WSGIServer(('', 5000), app)
    http_server.serve_forever()


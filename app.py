from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
#from wtforms import Form, StringField, TextAreaField,PasswordField, validators, HiddenField
#passlib.hash is used for encrypting our password we want to use. 
#from passlib.hash import sha256_crypt
import mysql.connector
#from wtforms.fields.html5 import EmailField
#from sumy.parsers.plaintext import PlaintextParser
#from sumy.nlp.tokenizers import Tokenizer
#from sumy.summarizers.lex_rank import LexRankSummarizer
from urllib.request import urlopen
from bs4 import BeautifulSoup
#from transformers import pipeline
import time
#import docx2txt
from functools import wraps

app = Flask(__name__)
app.secret_key='123hfh'

"""config = {
  'user': 'root',
  'password':'root',
  'host': 'localhost',
  'unix_socket': '/Applications/MAMP/tmp/mysql/mysql.sock',
  'database': 'nlp',
  'raise_on_warnings': True
}


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, *kwargs)
        else:
            flash('Unauthorized, Please login first and then use the system', 'danger')
            return redirect(url_for('login'))
    return wrap


def not_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            flash('Unauthorized, You logged in', 'danger')
            return redirect(url_for('register'))
        else:
            return f(*args, *kwargs)
    return wrap"""

"""
#A class for registration form 
class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=3, max=50)], render_kw={'autofocus': True})
    username = StringField('Username', [validators.length(min=3, max=25)])
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.length(min=4, max=25)])
    password = PasswordField('Password', [validators.length(min=3)])
@app.route('/', methods=['GET', 'POST'])
@not_logged_in
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cnx = mysql.connector.connect(**config)

        cur = cnx.cursor(dictionary=True)

        # Create Cursor
        #cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))

        # Commit cursor
        #mysql.connection.commit()

        # Close Connection
        cur.close()

        flash('You are now registered and can login', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


class LoginForm(Form):    # Create Message Form
    username = StringField('Username', [validators.length(min=1)], render_kw={'autofocus': True})

# User Login
@app.route('/login', methods=['GET', 'POST'])
@not_logged_in
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        # GEt user form
        username = form.username.data
        password_candidate = request.form['password']

        cnx = mysql.connector.connect(**config)

        cur = cnx.cursor(dictionary=True)

        # Create cursor
        #cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username=%s", [username])

        if result != 0:
            # Get stored value
            data = cur.fetchone()
            password = data['password']
            uid = data['id']
            name = data['name']

            # Compare password
            if sha256_crypt.verify(password_candidate, password):
                # passed
                session['logged_in'] = True
                session['uid'] = uid
                session['s_name'] = username
            

                return redirect(url_for('home'))

            else:
                flash('Incorrect password', 'danger')
                return render_template('login.html', form=form)

        else:
            flash('Username not found', 'danger')
            # Close connection
            cur.close()
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    if 'uid' in session:

        # Create cursor
        cnx = mysql.connector.connect(**config)

        cur = cnx.cursor(dictionary=True)
        uid = session['uid']
        session.clear()
        flash('You are logged out', 'success')
        return redirect(url_for('login'))
    return redirect(url_for('login'))

"""


@app.route('/home')
#@not_logged_in
def home():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
    
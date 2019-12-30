from flask import *
from flask_pymongo import *
from flask_jwt_extended import *
from flask_mail import Mail, Message
from flask_bcrypt import *
import uuid
import datetime as dt
import os
from datetime import datetime
import datetime as dt
from werkzeug import *


app = Flask(__name__)

EMAIL_USER = '-'
EMAIL_PASSWORD = '-'
UPLOAD_FOLDER = './static/img/'

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": EMAIL_USER,
    "MAIL_PASSWORD": EMAIL_PASSWORD
}




app.secret_key = "SECRET_KEY"
app.config["MONGO_URI"] = "mongodb://localhost:27017/contoso"
app.config['JWT_SECRET_KEY'] = 'SECRET_KEY'
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config.update(mail_settings)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
blacklist = set()

mongo = PyMongo(app)
jwt = JWTManager(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
from flask import Flask
from flask_httpauth import HTTPBasicAuth
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy

from api.config import Config

app = Flask(__name__)
app.config.from_object(Config)
auth = HTTPBasicAuth()

db = SQLAlchemy(app)
ma = Marshmallow(app)

from api import views


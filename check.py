import re
from google.appengine.ext import db
from string import letters

def valid_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password) and password

def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    return EMAIL_RE.match(email) or not email

def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username) and username

def valid_verified(password, verified):
    return password == verified

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

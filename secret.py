from libs.bcrypt import gensalt, hashpw
import hmac
import sys

sys.path.insert(0, '/libs')


secret = "WORDPRESS"

# all cookie and password stuff

def gen_salt():
    return gensalt()

def gen_secure_cookie(cookie):
    x = hmac.new(secret, cookie).hexdigest()
    return "%s|%s" % (cookie, x)


def check_secure_val(cookie):
    first, second = cookie.split("|")
    new_cookie = gen_secure_cookie(first)
    if new_cookie == cookie:
        return first

def gen_hash_password(username, password, salt = None):
    if not salt:
        salt = gen_salt()
    h = hashpw(username + password, salt)
    return "%s, %s" % (salt, h)


def valid_hash_password(username, password, hash):
    salt = hash.split(',')[0]
    return hash == gen_hash_password(username, password, salt)

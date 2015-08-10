#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os

import webapp2
import jinja2
from secret import *
from check import *
import geography
import json
import logging


from google.appengine.api import memcache
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def cache_func(username, update = False):
    key = 'top'
    blogs = memcache.get(key)
    if blogs is None or update:
        blogs = db.GqlQuery("select * from Blog where name =:name order by created desc", name = username)
        b = list(blogs)
        memcache.set(key, b)

    return blogs

class User(db.Model):
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, password, email = None):
        hash_func = gen_hash_password(name, password)
        return User(parent = users_key(), name = name, password = hash_func, email = email)


    @classmethod
    def login(cls, name, password):
        u = cls.by_name(name)
        if u and valid_hash_password(name, password, u.password):
            return u

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinji_env.get_template(template)
        return t.render(params)

    def set_secure_cookie(self, name, val):
        cookie = gen_secure_cookie(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie))


    def read_cookie(self, name):
        visits_cookie = self.request.cookies.get(name)
        return visits_cookie and check_secure_val(visits_cookie)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/')

    def initialize (self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json'
        self.write(json_txt)


# definition of cookies userid | gen
class loginHandler(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        user_name = self.request.get('username')
        password = self.request.get('password')
        print user_name, password
        u = User.login(user_name, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            self.render("login.html", error = "invalid login information", username = user_name)


class SignUpHandler(BaseHandler):

    def get(self):
        self.render('sign_up.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify_password = self.request.get('verify')
        email = self.request.get('email')

        name = valid_username(username)
        word = valid_password(password)
        mail = valid_email(email)
        verified = valid_verified(password, verify_password)

        params = dict(username = username, email = email)

        error = False

        if not name:
            params['error_username'] = 'Invalid Username'
            error = True
        if not word:
            params['error_password'] = 'Invalid Password'
            error = True
        elif not verified:
            params['error_verify'] = 'Password not same'
            error = True
        if not mail:
            params['error_email'] = 'invalid email'
            error = True
        if error:
            self.render('sign_up.html', **params)
        if User.by_name(username):
            error = True
            params['error_username'] = 'Username Already Exists'
            self.render('sign_up.html', **params)
        if error == False:
            a = User.register(username, password, email)
            a.put()
            self.login(a)
            self.redirect("/blog")


def blog_key(name = 'default'):
    return db.Key.from_path('blog', name)

class Blog(db.Model):
    title = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    name = db.StringProperty(required = True)
    lastModified = db.DateTimeProperty(auto_now = True)
    coords = db.GeoPtProperty()

    def render(self):

        # how to get username from here
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str("browser.html", b = self)


    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.title,
             'content': self.text,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.lastModified.strftime(time_fmt)}

        return d



class blog(BaseHandler):
    def get(self):
        if self.user:
            user_name = self.user.name
            self.render("blog.html", username = user_name)

    def post(self):
        username = self.user.name
        logout = self.request.get("logout")
        see = self.request.get("see")
        if logout:
            self.logout()
        if see:
            self.redirect('/browse')
        title = self.request.get("title")
        blogs = self.request.get("blog")
        if blogs:
            if not title:
                title = "Untitled"

            coords = geography.get_coords(self.request.remote_addr)
            print coords
            b = Blog(title = title, text = blogs, name = username)
            if coords:
                b.coords = coords
            b.put()
            self.redirect('/%s' % str(b.key().id()))
        else:
            self.render("blog.html", error = "no text input")


class browseHandler(BaseHandler):
    def get(self):
        username = self.user.name
        b = cache_func(username)
        if self.format == 'html':
            self.render("browser.html", b = b, username = username)
        else:
            return self.render_json([p.as_dict() for p in b])


class PostPage(BaseHandler):
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id))
        p = db.get(key)
        cache_func(self.user.name, update = True)

        if not p:
            self.redirect('/error')
            return
        if self.format == 'html':
            self.render("review.html", title = p.title, blog = p.text)
        else:
            self.render_json(p.as_dict())



    def post(self, post_id):
        review = self.request.get('review')
        if review:
            self.redirect('/browse')

class LocationHandler(BaseHandler):
    def get(self):
        b = db.GqlQuery("select * from Blog")
        b = list(b)

        #find blogs' urls
        points = filter(None, (a.coords for a in b))
        img_url = None
        if points != None:
            img_url = geography.gmaps_img(points)
        self.render("location.html", img_url = img_url)





class ErrorHandler(BaseHandler):
    def get(self):
        self.render("error.html")

app = webapp2.WSGIApplication([
    ('/', loginHandler),
    ('/signup', SignUpHandler),
    ('/blog', blog),
    ('/browse(?:\.json)?', browseHandler),
    ('/([0-9]+)(?:\.json)?', PostPage),
    ('/error', ErrorHandler),
    ('/location', LocationHandler)
], debug=True)

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
import cgi
import re
import hashlib
import hmac
import random
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape = True)
SECRET = "imasecret"
def render_str(template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val


class BaseHandler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render(self, template, **kw):
		self.response.out.write(render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val=self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)
	
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	#def initialize(self, *a, **kw):
		#webapp2.RequestHandler.initialize(self, *a, **kw)
		#uid = self.read_secure_cookie('user_id')
		#self.user = uid and User.by_id(int(uid))  ## this function will help to keep user logged in for all pages in site


###USER stuff
def make_salt():
	salt = ''
	for i in range(5):
		i=random.choice(string.letters)
		salt = i + salt
	return salt

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

def users_key(group='default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash= make_pw_hash(name, pw)
		return User(parent = users_key(), name=name, pw_hash=pw_hash, email=email)
		##note does not 'put' user

	@classmethod
	def login(cls, name, pw):
		u=cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


	


# write function to check valid username
user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
  return user_re.match(username)

# write function to check valid password
pass_re = re.compile(r"^.{3,20}$")
def valid_password(password):
  return pass_re.match(password)

# write function to check valid email
email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
  if email == '': return True
  else: return email_re.match(email)

# write function to compare check the passwords
def password_check(password, verify):
  if password == verify: return True
  else: return False

 # regular expression for cookie
COOKIE_RE = re.compile(r'.+=;\s*Path=/')
def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)



	
class Signup(BaseHandler):
	def get(self):
		self.render('signup.html')

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		


		params = dict(username = username, email = email)
		u= User.by_name(username)

		if u:
			params['error_username'] = "That user already exists"
			have_error=True
		if not valid_username(username):
			params['error_username'] = "That's not a valid username"
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match"
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email"
			have_error = True

		if have_error:
			self.render('signup.html', **params)

		else:
			u= User.register(username, password, email)
			u.put()
			cookie_val = make_secure_val(username)
			self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/' % (str(cookie_val)))

			#self.login(u)
			self.redirect('/welcome')

	

class Login(BaseHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		username=self.request.get('username')
		password=self.request.get('password')
		
		u=User.login(username, password)

		if u:
			self.login(u)
			self.redirect('/welcome')

		else:
			msg= "Invalid login"
			self.render('login.html', error_login=msg)


class Logout(BaseHandler):
	### clear cookie and redirect to signup
	def get(self):
		self.logout()
		self.redirect('/signup')

class Welcome(BaseHandler):
	
	def get(self):
		username = self.request.cookies.get('user_id') 
		val = check_secure_val(username) 
		self.render('welcome.html', username=val)

	
        
app = webapp2.WSGIApplication([('/', BaseHandler),
	('/signup', Signup), ('/welcome', Welcome), ('/login', Login), ('/logout', Logout)], debug=True)

import os
import re
import random
import hashlib
import hmac
import json
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

secret = 'du.uybghfg+h9fg0h8fghg^~gh'

# Defines the database model for posts
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	#permalink = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render_str(template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def make_secure_val(val):
		return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

	def check_secure_val(secure_val):
		val = secure_val.split('|')[0]
		if secure_val == make_secure_val(val):
			return val

# The BlogHandler based on Google's HTTP RequestHandler
class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		def make_secure_val(val):
			return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
		
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		def check_secure_val(secure_val):
			def make_secure_val(val):
				return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
			val = secure_val.split('|')[0]
			if secure_val == make_secure_val(val):
				return val
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

	def render_post(response, post):
		response.out.write('<b>' + post.subject + '</b><br>')
		response.out.write(post.content)
		
# The JSON class that dumps all blog posts in JSON format
class Json(BlogHandler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
		
		url1 = self.request.url
		if url1.find('/json') > 0:
			self.response.out.write("{")
			
			for post in posts:
				self.response.out.write(json.dumps({"content":post.content, "created":post.created.strftime("%d.%m.%Y @ %H:%M"), "last_modified":post.last_modified.strftime("%d.%m.%Y @ %H:%M"), "subject":post.subject}, sort_keys=True, indent=4, separators=(',', ': ')))

			self.response.out.write("}")
		else:
			self.render('index.html', posts = posts)
		
# Render a single post
# Dumps blog post in JSON format if post ends with .json
class Permalink(BlogHandler):
	def get(self, post_id):
		url1 = self.request.url
		if url1.find('json') > 0:
			start = 'com/'
			end = '.json'
			postid = (url1.split(start))[1].split(end)[0]
			
			post = Post.get_by_id(int(postid))
			if not post:
				self.error(404)
				return
			else:
				self.response.out.write(json.dumps({"content":post.content, "created":post.created.strftime("%d.%m.%Y @ %H:%M"), "last_modified":post.last_modified.strftime("%d.%m.%Y @ %H:%M"), "subject":post.subject}, sort_keys=True, indent=4, separators=(',', ': ')))
		else:
			post = Post.get_by_id(int(post_id))
			if not post:
				self.error(404)
				return
			else:
				self.render("index.html", posts = [post])

# The blog
class MainPage(BlogHandler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")

		if self.user:
			self.render('index.html', posts = posts, username = self.user.name)
		else:
			self.render('index.html', posts = posts)

# Defines the database model for users
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		def users_key(group = 'default'):
			return db.Key.from_path('users', group)
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register (cls, name, pw, email = None):
		def make_pw_hash(name, pw, salt = None):
			def make_salt(length = 5):
				return ''.join(random.choice(letters) for x in xrange(length))
			
			if not salt:
				salt = make_salt()
			h = hashlib.sha256(name + pw + salt).hexdigest()
			return '%s,%s' % (salt, h)
			
		def users_key(group = 'default'):
			return db.Key.from_path('users', group)
	
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
			name = name,
			pw_hash = pw_hash,
			email = email)

	@classmethod
	def login(cls, name, pw):
		def valid_pw(name, password, h):
			def make_pw_hash(name, pw, salt = None):
				def make_salt(length = 5):
					return ''.join(random.choice(letters) for x in xrange(length))
				
				if not salt:
					salt = make_salt()
				h = hashlib.sha256(name + pw + salt).hexdigest()
				return '%s,%s' % (salt, h)
			
			salt = h.split(',')[0]
			return h == make_pw_hash(name, password, salt)
		
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

# Signup
class Signup(BlogHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
				email = self.email)
				
		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		def valid_username(username):
			return username and USER_RE.match(username)
			
		PASS_RE = re.compile(r"^.{3,20}$")
		def valid_password(password):
			return password and PASS_RE.match(password)
			
		EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
		def valid_email(email):
			return not email or EMAIL_RE.match(email)

		if not valid_username(self.username):
			params['error_username'] = "Your username is not valid!"
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "Your password is not valid!"
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords did not match!"
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "The email address provided is not valid!"
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

# Register method based on Signup
class Register(Signup):
	def done(self):
		#make sure the user doesnt't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'The user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.redirect('/welcome')

# The login
class Login(BlogHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/welcome')
		else:
			msg = 'The username and/or password is not correct'
			self.render('login-form.html', error = msg)

# The logout
class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/')

# Welcome page
class Welcome(BlogHandler):
	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/login')
			
# Submission form for new post
class NewPost(BlogHandler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		#permalink = subject.replace(" ", "-")

		if subject and content:
			post = Post(subject = subject, content = content)
			#post = Post(subject = subject, content = content, permalink = permalink)
			
			key = post.put()
			self.redirect("/%d" % key.id())
		else:
			error = "Both subject and content is mandatory!"
			self.render("newpost.html",subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([('/', MainPage),
				('/newpost', NewPost),
				('/(\d+)', Permalink),
				('/(\d+.json)', Permalink),
				('/json', Json),
				('/signup', Register),
				('/login', Login),
				('/logout', Logout),
				('/welcome', Welcome),
				],
				debug=True)
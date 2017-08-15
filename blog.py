import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'ThisIsAVeryComplicatedStringSoYouNeverCanGuessItLOL'
userRegex = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
mailRegex = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
passwordRegex = re.compile(r"^.{3,20}$")


def render_str(template, **paramet):
    t = jinja_env.get_template(template)
    return t.render(paramet)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class MainHandle(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **paramet):
        paramet['user'] = self.user
        return render_str(template, **paramet)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('uid222', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'uid222=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('uid222')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(MainHandle):

    def get(self):
        self.write('<h1><b>Hello,</b></h1><h2>Udacity!</h2>')


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def checkpw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and checkpw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    # creator = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # id_ = db.id()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogFront(MainHandle):

    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(MainHandle):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(MainHandle):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.render("error.html", error="Sorry, you arent permitted to do that!", title="No permission")

    def post(self):
        if not self.user:
            self.render("error.html", error="Sorry, you arent permitted to do that!", title="No permission")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content, creator=creator)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please! :)"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


def checkusername(username):
    return username and userRegex.match(username)


def checkpassword(password):
    return password and passwordRegex.match(password)


def checkemail(email):
    return not email or mailRegex.match(email)


class SignupUser(MainHandle):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        error1 = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        paramet = dict(username=self.username,
                       email=self.email)

        if not checkusername(self.username):
            paramet['error_username'] = "That's not a valid username. :("
            error1 = True

        if not checkpassword(self.password):
            paramet['error_password'] = "That wasn't a valid password. :("
            error1 = True
        elif self.password != self.verify:
            paramet['error_verify'] = "Your passwords didn't match. :("
            error1 = True

        if not checkemail(self.email):
            paramet['error_email'] = "That's not a valid email. :("
            error1 = True

        if error1:
            self.render('signup-form.html', **paramet)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class RegisterUser(SignupUser):

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists. :('
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class LoginUser(MainHandle):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login data :('
            self.render('login-form.html', error=msg)


class LogOutUser(MainHandle):

    def get(self):
        self.logout()
        self.redirect('/blog')


class WelcomeUser(MainHandle):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

class ImATeapot(webapp2.RequestHandler):
	def get(self):
		self.error(418)



app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', RegisterUser),
                               ('/login', LoginUser),
                               ('/logout', LogOutUser),
                               ('/unit3/welcome', WelcomeUser),
                               ('/teapot', ImATeapot)
                               ],
                              debug=True)

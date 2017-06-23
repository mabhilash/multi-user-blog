import os
import re
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db
import webapp2
import jinja2
from user import User
from comment import Comment
from post import Post
from likes import Likes

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'value_master'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    """This method crates a secure value using secret string"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    """Verification of secure value"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    """This class inherits webapp2  and provides helper methods"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """This method sets the cookie to browser"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """This method reads the secure cookie from browser"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """This method verifies if user already exists"""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """This method removes the login information from cookie when logged out"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """This method is initialized for each page and checks the login information and cookie value"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      #self.write('Hello, Udacity!')
      posts = greetings = Post.all().order('-created')
      self.render('front.html', posts=posts)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class BlogFront(BlogHandler):
    """This class retrieves the data on to the front page"""
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class LikePost(BlogHandler):
    """This class handles the Like functionality of the multi-user-blog"""
    def get(self,post_id):
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)
        if self.user:
            if post.user_id == self.user.key().id():
                self.redirect('/blog/'+post_id+"?error=You cannot like your own post")
            else:
                likes = Likes.all().filter('user_id =', self.user.key().id()).filter('post_id =', post_id).get()
                if likes:
                    self.redirect('/blog/'+post_id+"?error=You already liked the post")
                else:
                    like_post = Likes(parent = blog_key(), user_id=self.user.key().id(), post_id = post_id)
                    like_post.put();
                    self.redirect('/blog/'+post_id)
        else:
            self.redirect('/blog/'+post_id+"?error=You need to login to like the post")

class CommentPost(BlogHandler):
    """This class handles the Comment functionality of the multi-user-blog"""
    def get(self,post_id):
        self.render('addcomment.html')
    def post(self,post_id):
        key=db.Key.from_path('Post', int(post_id), parent = blog_key())
        post=db.get(key)
        if self.user:
            if self.request.get('comment'):
                c=Comment(parent=blog_key(),user_name=self.user.name, user_id=self.user.key().id(), post_id=post_id, comment=self.request.get('comment'))
                c.put()
                self.redirect('/blog/'+post_id)
            else:
                self.redirect('/blog/'+post_id+'?error=Enter a comment to submit')
        else:
            self.redirect('/blog/'+post_id+'?error=You need to login to commment')


class PostPage(BlogHandler):
    """This class renders the details of a particular blog entry(Likes,Comments,Edit,Delete)"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likesKey=Likes.all().filter('post_id =',post_id).count()
        comments= Comment.all().filter('post_id =',post_id)
        if not post:
            self.error(404)
            return
        error=self.request.get('error')
        self.render("permalink.html", post = post, numLikes=likesKey, comments=comments, error=error)
    def post(self,post_id):
        key=db.Key.from_path('Post', int(post_id), parent = blog_key())
        post=db.get(key)
        if self.user:
            if(self.request.get('comment')):
                c=Comment(parent=blog_key(),user_name=self.user.name, user_id=self.user.key().id(), post_id=post_id, comment=self.request.get('comment'))
                c.put()
                self.redirect('/blog/'+post_id)
                comments= Comment.all().filter('post_id =',post_id)
        else:
            self.redirect('/blog/'+post_id+'?error=You need to login to comment')

class NewPost(BlogHandler):
    """This class handles posting new blog content functionality"""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), user_id=self.user.key().id(),  subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

"""The valid_username method checks if the username is of particular format """
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

"""The valid_password method checks if the password is valid and has particular format """
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

"""The valid_email method checks if the email format is valid """
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    """This class handles sign up of new user"""
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

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        """Checks if user already exists"""
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            #self.redirect('/blog')
            self.redirect('/')

class Login(BlogHandler):
    """This class handles login functionality of multi-user-blog"""
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    """This class handles logout functionality of multi-user-blog"""
    def get(self):
        self.logout()
        self.redirect('/blog')

class EditPost(BlogHandler):
    """This class handles editing an already existing post functionality"""
    def get(self, post_id):
        if self.user:
            key=db.Key.from_path('Post', int(post_id), parent=blog_key())
            post=db.get(key)
            if post.user_id == self.user.key().id():
                self.render('editpost.html', subject= post.subject, content= post.content)
            else:
                permission_denied='You do not have permission to edit the record'
                self.redirect('/blog/'+post_id+'?error=You do not have permission to edit the post')
                #self.render('permalink.html',post=post, permission_denied= permission_denied)
                #self.write('You do not have permission to edit the post')
        else:
            self.redirect('/blog/'+post_id+'?error=You need to login to edit the post')
            #self.render('permalink.html', no_login= no_login, post=post)

    def post(self,post_id):
        subject=self.request.get('subject')
        content=self.request.get('content')
        if self.request.get('cancel'):
            self.redirect('/blog/'+post_id)
        if subject and content:
            key=db.Key.from_path('Post', int(post_id), parent=blog_key())
            post=db.get(key)
            post.subject=subject
            post.content=content
            post.put()
            self.redirect('/blog/%s' %post_id)
        else:
            error='Subject and content cannot be empty'
            self.render('newpost.html',subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
    """This class handles the delete functionality of the existing post"""
    def get(self, post_id):
        if self.user:
            key=db.Key.from_path('Post', int(post_id), parent= blog_key())
            del_post=db.get(key)
            if del_post.user_id== self.user.key().id():
                del_post.delete()
                self.redirect('/')
                
            else:
                del_permsn='You do not have accees to delete this post'
                self.redirect('/blog/'+post_id+'?error=%s' %del_permsn)
                
        else:
            no_login='You need to login to delete the post'
            self.redirect('/blog/'+post_id+'?error=%s' %no_login)



class DeleteComment(BlogHandler):
    """This class handles deleting of comments"""
    def get(self,post_id,comment_id):
        key=db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment=db.get(key)
        if self.user:
            if comment.user_id == self.user.key().id():
                comment.delete()
                self.redirect('/blog/'+post_id+'?error=Comment has been deleted')
            else:
                self.redirect('/blog/'+post_id+'?error=You cannot delete this comment')
        else:
            self.redirect('/blog/'+post_id+'?error=Please login to delete the comment')


class EditComment(BlogHandler):
    """This class handles the editing functionality of the comments in multi-user-blog"""
    def get(self, post_id, comment_id):
        if self.user:
            key=db.Key.from_path('Comment', int(comment_id), parent= blog_key())
            cmnt=db.get(key)
            if cmnt.user_id == self.user.key().id():
                self.render('editcomment.html', editcomment= cmnt.comment)
            else:
                self.redirect('/blog/'+post_id+'?error=You do not have permission to edit the comment')
        else:
            self.redirect('/blog/'+post_id+'?error=You need to login to edit the comment')
    def post(self, post_id, comment_id):
        if self.request.get('comment'):
            key=db.Key.from_path('Comment', int(comment_id), parent= blog_key())
            comment=db.get(key)
            comment.comment=self.request.get('comment')
            comment.put()
            self.redirect('/blog/'+post_id)
        else:
            self.redirect('/blog/'+post_id+'/'+comment_id+'?error=Enter a comment')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/like/([0-9]+)',LikePost),
                               ('/blog/comment/([0-9]+)',CommentPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',EditComment)
                               ],
                              debug=True)

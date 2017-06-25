from google.appengine.ext import db
from user import User
import main


class Post(db.Model):
	user_id = db.IntegerProperty(required=True)
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return main.render_str("post.html", p=self)

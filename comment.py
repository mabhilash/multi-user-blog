from google.appengine.ext import db


class Comment(db.Model):
    user_id=db.IntegerProperty(required=True)
    post_id=db.StringProperty(required=True)
    comment=db.TextProperty(required=True)

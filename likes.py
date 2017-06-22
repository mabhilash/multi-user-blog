from google.appengine.ext import db


class Likes(db.Model):
    user_id = db.IntegerProperty(required = True)
    post_id = db.StringProperty(required = True)

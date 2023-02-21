import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor,CKEditorField
from datetime import date
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,validators,PasswordField
from wtforms.validators import DataRequired, URL,Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
import email_validator
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import os

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager=LoginManager()
login_manager.init_app(app)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)








##CONFIGURE TABLES



class User(db.Model,UserMixin):
    __tablename__='user'
    id= db.Column(db.Integer,primary_key=True)


    email=db.Column(db.String(250),unique=True,nullable=False)
    password= db.Column(db.String(250),nullable=False)
    name= db.Column(db.String(250),nullable=False)
    posts=relationship('BlogPost',back_populates='author')
    comment_posts=relationship('Comment',back_populates='user_comment')

class BlogPost(db.Model,UserMixin):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    blog_comment= relationship('Comment',back_populates='author_comment')
class Comment(UserMixin,db.Model):
    __tablename__ ="Comments"
    id=db.Column(db.Integer,primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user_comment = relationship('User', back_populates='comment_posts')
    author_id_blog = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_comment=relationship('BlogPost',back_populates='blog_comment')
    comment = db.Column(db.String(250), nullable=False)








class RegisterForm(FlaskForm):
    email= StringField('email',validators=[DataRequired() ,Email()])
    password= PasswordField('password',validators=[DataRequired()])
    name=StringField('name',validators=[DataRequired()])
    submit=SubmitField('Sign in')
class LoginForm(FlaskForm):
    email=StringField('email',validators=[DataRequired(),Email()])
    password=PasswordField('password',validators=[DataRequired(),Email()])
    submit=SubmitField('Log in')
class CommentForm(FlaskForm):
    comment=CKEditorField('Comment',validators=[DataRequired()])
    submit=SubmitField('Submit comment')

def admin_only(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.id != 1:
                return abort(403)
            return f(*args, **kwargs)

        return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    users=User.query.all()
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated,user=users)



@app.route('/register',methods=['POST','GET'])
def register():
    form=RegisterForm()
    if request.method=='POST':
        email=form.email.data
        password=form.password.data
        name=form.name.data
        new_user=User(email=email,password=werkzeug.security.generate_password_hash(password=password,method='pbkdf2:sha256',salt_length=8),name=name)
        try:
            db.session.add(new_user)
            db.session.commit()

        except :
            flash('This email already exist , try to log in instead')
            return redirect(url_for('login'))
        else:
            login_user(new_user)
            return redirect(url_for('login'))


    return render_template("register.html",form=form)


@app.route('/login',methods=['POST','GET'])
def login():
    form=LoginForm()
    if request.method=='POST':
        password=form.password.data
        user_data=User.query.filter_by(email=form.email.data).first()
        if user_data:
            if werkzeug.security.check_password_hash(pwhash=user_data.password,password=password):
                login_user(user_data)
                return redirect(url_for('get_all_posts'))
            else:
               flash('The password is incorrect')
               return redirect(url_for('login'))
        else:
            flash('this email does not exist')
            return redirect(url_for('login'))


    return render_template("login.html",form=form)


@app.route('/logout')

def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['POST','GET'])

def show_post(post_id):
    form= CommentForm()
    all_comment=Comment.query.all()
    users=User.query.all()
    requested_post = BlogPost.query.get(post_id)
    if request.method=='POST':
        if current_user.is_authenticated:
            comment=form.comment.data
            comment_to_add=Comment(comment=comment,user_comment=current_user,author_comment=requested_post)
            db.session.add(comment_to_add)
            db.session.commit()

        else:
            flash('you must log in to comment!')
            return redirect(url_for('login'))




    return render_template("post.html", post=requested_post,logged_in=current_user.is_authenticated,form=form,comments=all_comment)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['POST','GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>",methods=['GET','POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data

        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)

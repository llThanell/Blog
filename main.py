from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import smtplib

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

my_email = "nguyennam2741@yahoo.com"
my_password = "G-5*EqpY!mLrijH"

gravatar = Gravatar(app, size=30, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=False, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), unique=False, nullable=False)
    
    #This will act like a List of BlogPost objects attached to each User. 
    posts = relationship("BlogPost", back_populates="author")
    cmt = relationship("Comment", back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="blog_post")

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="cmt")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blog_post = relationship("BlogPost", back_populates="comments")

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)


db.create_all()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)

#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)        
    return decorated_function

@app.route('/register', methods=["GET", "POST"])
def register():
    user = RegisterForm()
    if user.validate_on_submit():
        email = User.query.filter_by(email=user.email.data).first()
        if email:
            flash("You have been registered with the same email address, please login!")
            return redirect(url_for('login'))
        new_user = User(
            name=user.name.data,
            email=user.email.data,
            password=generate_password_hash(user.password.data, method='pbkdf2:sha256', salt_length=8),
        )
        db.session.add(new_user)
        db.session.commit()

        #This line will authenticate the user with Flask-Login.
        login_user(new_user)
        return redirect(url_for('login'))
    return render_template("register.html", form=user, logged_in=current_user.is_authenticated)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=["GET", "POST"])
def login():
    login = LoginForm()
    if login.validate_on_submit():
        user = User.query.filter_by(email=login.email.data).first()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))  
        #Check stored password hash against entered password hashed.
        elif check_password_hash(user.password, login.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else: 
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
    return render_template("login.html", form=login, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    cmt_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if cmt_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=cmt_form.cmt.data,
            author=current_user,
            blog_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=cmt_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id=current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        send_message(form)
        return render_template("contact.html", msg_sent=True, form=form)
    return render_template("contact.html", msg_sent=False, form=form)

def send_message(form):
    people_message = f"Blog Message\n\nYou have message from {form.email.data} \nName: {form.name.data}\nPhone: {form.phone_num.data}\nMessage: \n{form.message.data}\n"
    # ⚡ My email address does not work at the moment so I commented this code.
    # if "yahoo" in form.email.data:
    #     with smtplib.SMTP("smtp.mail.yahoo.com") as connection:
    #         connection.starttls()
    #         connection.login(user=my_email, password=my_password)
    #         connection.sendmail(from_addr=my_email, to_addrs="ntguppy13@gmail.com", msg=people_message, logged_in=current_user.is_authenticated)
    # else:
    #     with smtplib.SMTP("smtp.gmail.com") as connection:
    #         connection.starttls()
    #         connection.login(user=my_email, password=my_password)
    #         connection.sendmail(from_addr=my_email, to_addrs="ntguppy13@gmail.com", msg=people_message, logged_in=current_user.is_authenticated)
    
if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

    

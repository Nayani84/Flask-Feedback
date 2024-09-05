from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from werkzeug.exceptions import Unauthorized

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///flask_feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


app.app_context().push()
app.app_context()

connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)

@app.route("/")
def homepage():
    """home page."""

    return redirect("/register")



@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Show User Signup form and handle the form."""

    if "username" in session:
        return redirect(f"/users/{session['username']}")
    
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append(f'the username {username} exists, Please pick another username.')
            return render_template('register.html', form=form)
        
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f"/users/{new_user.username}")

    return render_template('create_user.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Show User Login form and handle the form."""

    if "username" in session:
        return redirect(f"/users/{session['username']}")
    
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f"/users/{user.username}")
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)



@app.route('/logout')
def logout_user():
    """User logout."""

    session.pop('username')
    flash("Goodbye!", "info")
    return redirect('/')



@app.route('/users/<username>')
def show_user(username):
    """Show info on a User."""

    if "username" not in session or username!= session['username']:
        flash("You must be logged in to view", "danger")
        return redirect('/login')
        
    else:
        user = User.query.get_or_404(username)

        return render_template("secret.html", user=user)
    


@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    """Delete User."""

    if 'username' not in session or username != session['username']:
        flash("Please login first!", "danger")
        return redirect('/login')
    
    user = User.query.get_or_404(username)
    if username == session['username']:
        db.session.delete(user)
        db.session.commit()
        session.pop("username")
        flash("User deleted!", "info")
        return redirect('/')
    
    flash("You don't have permission to do that!", "danger")
    return redirect('/login')

    

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def new_feedback(username):
    """Show create Feedback form and handle the form."""

    if "username" not in session or username != session['username']:
        flash("Please login first!", "danger")
        return redirect('/login')

    form = FeedbackForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        new_feedback = Feedback(title=title, content=content, username=username)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback Created!', 'success')
        return redirect(f"/users/{new_feedback.username}")

    return render_template("create_feedback.html", form=form)



@app.route("/feedback/<int:feedback_id>/update", methods=["GET", "POST"])
def update_feedback(feedback_id):
    """Show update Feedback form and handle the form."""

    feedback = Feedback.query.get_or_404(feedback_id)

    if "username" not in session or feedback.username != session['username']:
        flash("Please login first!", "danger")
        return redirect('/login')
    
    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data

        db.session.commit()

        return redirect(f"/users/{feedback.username}")

    return render_template("feedback_edit.html", form=form, feedback=feedback)



@app.route('/feedback/<int:feedback_id>/delete', methods=["POST"])
def delete_feedback(feedback_id):
    """Delete feedback."""

    feedback = Feedback.query.get_or_404(feedback_id)

    if 'username' not in session or feedback.username != session['username']:
        flash("Please login first!", "danger")
        return redirect('/login')
    
    
    if feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted!", "info")
        return redirect(f"/users/{feedback.username}")
    
    flash("You don't have permission to do that!", "danger")
    return redirect('/login')

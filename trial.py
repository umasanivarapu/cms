from flask import Flask,render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, TextField
from wtforms.validators import InputRequired, Email, Length

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secret!'
Bootstrap(app)

class LoginForm(FlaskForm):
	username = StringField('username',validators=[InputRequired(), Length(min=3, max=20 )])
	password = PasswordField('password',validators=[InputRequired(), Length(min=8, max=80)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username',validators=[InputRequired(), Length(min=3, max=20 )])
	password = PasswordField('password',validators=[InputRequired(), Length(min=8, max=80)])

class Profile(FlaskForm):
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])

class LodgeComplaint(FlaskForm):
	summary = TextField('Write Your Complaint', validators=[InputRequired(), Length(min=5)])





@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		return form.username.data + ' ' +form.password.data
	return render_template('login.html',form = form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		return form.username.data + ' ' + form.email.data + ' ' + form.password.data

	return render_template('signup.html',form = form)

@app.route('/usersettings', methods=['GET','POST'])
def usersettings():
	form = Profile()

	if form.validate_on_submit():
		return form.first_name.data

	return render_template('usersettings.html',form = form)

@app.route('/userlodgecomplaint', methods=['GET','POST'])
def userlodgecomplaint():
	form = LodgeComplaint()

	if form.validate_on_submit():
		return form.summary.data

	return render_template('userlodgecomplaint.html',form = form)


@app.route('/userhistory')
def userhistory():
	return render_template('userhistory.html')

@app.route('/dashboard')
def dashboard():
	return render_template('dashboard.html')


if __name__ == '__main__':
	app.run(debug=True)
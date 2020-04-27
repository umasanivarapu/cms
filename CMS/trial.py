from flask import Flask,render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, TextField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash

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

class UserProfile(FlaskForm):
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])

class AdminProfile(FlaskForm):
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	# department = StringField('Department', validators=[InputRequired(), Length(max=30)])

class SuperAdminProfile(FlaskForm):
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])


class LodgeComplaint(FlaskForm):
	subject = TextField('Subject of the complaint', validators=[InputRequired()])
	summary = TextField('Write Your Complaint', validators=[InputRequired(), Length(min=5)])


class AddRemoveAdmin(FlaskForm):
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])

class AddRemoveDivision(FlaskForm):
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])

class AddRemoveDepartment(FlaskForm):
	department = StringField('Department', validators=[InputRequired(), Length(max=30)]) 






#-------------------------------------------- -------------------Initial Page---------------------------------------------------------------------------#

@app.route('/')
def base1():
    return render_template('base1.html')

#------------------------------------------------------------------User--------------------------------------------------------------------------------#

@app.route('/user')                                              #login page
def user():
    return render_template('user.html')

@app.route('/signup', methods=['GET', 'POST'])                       #Signup
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		username = form.username.data
		email = form.email.data
		password = generate_password_hash(form.password.data, "sha256") #converts password into it's hash
		print(username)
		print(email)
		print(password)
		return render_template('afteruserloggedin.html')

	return render_template('signup.html',form = form)

@app.route('/userlogin', methods=['GET','POST'])                              #Login
def userlogin():
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember = form.remember.data
		hashed_pass = generate_password_hash(password, "sha256")
		print (check_password_hash(hashed_pass, password)) 
		print(username)
		print(password)
		print(remember)
		return render_template('afteruserloggedin.html')
	return render_template('userlogin.html',form = form)


@app.route('/afteruserloggedin')                                   #user page
def afteruserloggedin():
    return render_template('afteruserloggedin.html')


@app.route('/usersettings', methods=['GET','POST'])                  #user settings
def usersettings():
	form = UserProfile()

	if form.validate_on_submit():
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		dept =  form.department.data
		print(first_name)
		print(last_name)
		print(age)
		print(dept)
		return render_template('afteruserloggedin.html')

	return render_template('usersettings.html',form = form)

@app.route('/userlodgecomplaint', methods=['GET','POST'])                  # lodge complaint
def userlodgecomplaint():
	form = LodgeComplaint()

	if form.validate_on_submit():
		subject = form.subject.data
		summary = form.summary.data
		print(subject)
		print(summary)
		return render_template('afteruserloggedin.html')

	return render_template('userlodgecomplaint.html',form = form)


@app.route('/userhistory')                                                #complaint history
def userhistory():
	return render_template('userhistory.html')

#-----------------------------------------------------------------------------------------------------------------------------------------------------#


#--------------------------------------------------------------------Admin-----------------------------------------------------------------------------#

    
@app.route('/admin')                                             #login
def admin():
    return render_template('admin.html')


@app.route('/adminlogin', methods=['GET','POST'])                              #Login
def adminlogin():
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember = form.remember.data
		hashed_pass = generate_password_hash(password, "sha256")
		print (check_password_hash(hashed_pass, password)) 
		print(username)
		print(password)
		print(remember)
		return render_template('afteradminloggedin.html')
	return render_template('adminlogin.html',form = form)


@app.route('/afteradminloggedin')                                   #Admin Page
def afteradminloggedin():
    return render_template('afteradminloggedin.html')


@app.route('/adminsettings', methods=['GET','POST'])                     # Settings
def adminsettings():
	form = AdminProfile()

	if form.validate_on_submit():
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		# dept =  form.department.data
		print(first_name)
		print(last_name)
		print(age)
		# print(dept)
		return render_template('afteradminloggedin.html')

	return render_template('adminsettings.html',form = form)

@app.route('/adminresolvecomplaint')                                            #Resolve Complaint
def adminresolvecomplaint():
    return render_template('adminresolvecomplaint.html')

   
@app.route('/adminhistory')                                               #Admin history
def adminhistory():
    return render_template('adminhistory.html')

#--------------------------------------------------------------------------------------------------------------------------------------------------------#
#---------------------------------------------------------------------Super Admin------------------------------------------------------------------------#

@app.route('/superadmin')
def superadmin():
    return render_template('superadmin.html')

@app.route('/superadminlogin', methods=['GET','POST'])                              #Login
def superadminlogin():
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember = form.remember.data
		hashed_pass = generate_password_hash(password, "sha256")
		print (check_password_hash(hashed_pass, password)) 
		print(username)
		print(password)
		print(remember)
		return render_template('aftersuperadminloggedin.html')
	return render_template('superadminlogin.html',form = form)

@app.route('/aftersuperadminloggedin')
def aftersuperadminloggedin():
    return render_template('aftersuperadminloggedin.html')


@app.route('/superadmin_addadmin',methods=['GET','POST'])
def superadmin_addadmin():
	form = AddRemoveAdmin()

	if form.validate_on_submit():
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		dept = form.department.data
		division = form.division.data
		print(first_name)
		print(last_name)
		print(age)
		print(dept)
		print(division)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminaddadmin.html',form = form)

@app.route('/superadmin_removeadmin',methods=['GET','POST'])
def superadmin_removeadmin():
	form = AddRemoveAdmin()

	if form.validate_on_submit():
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		dept = form.department.data
		division = form.division.data
		print(first_name)
		print(last_name)
		print(age)
		print(dept)
		print(division)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminremoveadmin.html',form = form)

@app.route('/superadmin_adddivision', methods =['GET','POST'])
def superadmin_adddivision():
	form = AddRemoveDivision()

	if form.validate_on_submit():
		dept = form.department.data
		division = form.division.data
		print(dept)
		print(division)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminadddivision.html', form=form)
    
@app.route('/superadmin_removedivision',methods=['GET','POST'])
def superadmin_removedivision():
	form = AddRemoveDivision()

	if form.validate_on_submit():
		dept = form.department.data
		division = form.division.data
		print(dept)
		print(division)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminremovedivision.html',form=form)
    
@app.route('/superadmin_adddepartment',methods=['GET','POST'])
def superadmin_adddepartment():
	form = AddRemoveDepartment()

	if form.validate_on_submit():
		dept = form.department.data
		print(dept)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminadddepartment.html',form=form)


@app.route('/superadmin_removedepartment', methods=['GET','POST'])
def superadmin_removedepartment():
	form = AddRemoveDepartment()

	if form.validate_on_submit():
		dept = form.department.data
		print(dept)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminremovedepartment.html',form=form)

@app.route('/superadminsettings', methods=['GET','POST'])
def superadminsettings():
	form = SuperAdminProfile()

	if form.validate_on_submit():
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		dept =  form.department.data
		print(first_name)
		print(last_name)
		print(age)
		print(dept)
		return render_template('aftersuperadminloggedin.html')

	return render_template('superadminsettings.html',form = form)




#---------------------------------------------------------------------------------------------------------------------------------------------------------#







@app.route('/dashboard')
def dashboard():
	return render_template('dashboard.html')


if __name__ == '__main__':
	app.run(debug=True)
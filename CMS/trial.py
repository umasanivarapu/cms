from flask import Flask,render_template,request,session,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, TextField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from nocache import nocache


from app import app, cursor, db
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secret!'
Bootstrap(app)

class LoginForm(FlaskForm):
	username = StringField('username',validators=[InputRequired(), Length(min=3, max=50 )])
	password = PasswordField('password',validators=[InputRequired(), Length(min=8, max=80)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	# username = StringField('username',validators=[InputRequired(), Length(min=3, max=20 )])
	password = PasswordField('password',validators=[InputRequired(), Length(min=8, max=80)])
	firstname = StringField('firstname',validators=[InputRequired(),Length(min=2,max=30)])
	lastname = StringField('lastname',validators=[InputRequired(),Length(min=1,max=30)])
	age = IntegerField('Age',validators=[InputRequired()])

class UserProfile(FlaskForm):
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	# department = StringField('Department', validators=[InputRequired(), Length(max=30)])

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
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])
	passcode = StringField('passcode',validators=[InputRequired(),Length(min=5,max=20)])

class AddRemoveDivision(FlaskForm):
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])

class AddRemoveDepartment(FlaskForm):
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])

class RemoveAdmin(FlaskForm):
	adminemail = StringField('adminemail', validators=[InputRequired(), Length(max=30)])





user_name = ""
#-------------------------------------------- -------------------Initial Page---------------------------------------------------------------------------#

@app.route('/')
@nocache
def base1():
    return render_template('base1.html')

#------------------------------------------------------------------User--------------------------------------------------------------------------------#

@app.route('/user')
@nocache                                             #login page
def user():
    return render_template('user.html')

@app.route('/signup', methods=['GET', 'POST'])
@nocache                       #Signup
def signup():
	form = RegisterForm()
	if form.validate_on_submit():
		# username = form.username.data
		email = form.email.data
		# password = generate_password_hash(form.password.data, "sha256") #converts password into it's hash
		password = form.password.data
		firstname = form.firstname.data
		lastname  = form.lastname.data
		age = form.age.data
		user_name = email
		session['username'] = email
		print(user_name)
		print(email)
		print(password)
		cursor.execute("insert into users values(%s,%s,%s,%s,%s)",(email,password,firstname,lastname,age))
		db.commit()
		return render_template('afteruserloggedin.html')

	return render_template('signup.html',form = form)

@app.route('/userlogin', methods=['GET','POST'])
@nocache                              #Login
def userlogin():
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember = form.remember.data
		user_name = username
		session['username'] = username
		print(user_name)
		# hashed_pass = generate_password_hash(password, "sha256")
		sql = "select user_id,password from users where user_id = '{0}'"
		cursor.execute(sql.format(username))
		res = cursor.fetchall()

		# print (check_password_hash(hashed_pass, password))
		print(username)
		print(password)
		print(remember)
		if str(res[0][1]) == password:                      #else parts should be written
			return render_template('afteruserloggedin.html')
	return render_template('userlogin.html',form = form)


@app.route('/afteruserloggedin')
@nocache                               #user page
def afteruserloggedin():
    return render_template('afteruserloggedin.html')

@app.route('/userprofileinfo',methods = ['POST', 'GET'])
@nocache      #user profile info
def userprofileinfo():

	sql = "select firstname,lastname,age from users where user_id = '{0}'"
	cursor.execute(sql.format(session['username']))
	resultx = cursor.fetchall()
	result1 = dict()
	result1["first_name"] = resultx[0][0]
	result1["last_name"] = resultx[0][1]
	result1["age"] = resultx[0][2]
	result1["dept"] = "dept"
	return render_template('userprofileinfo.html',result = result1)


@app.route('/usersettings', methods=['GET','POST'])
@nocache                 #user settings
def usersettings():
	form = UserProfile()

	if form.validate_on_submit():
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		# dept =  form.department.data
		cursor.execute("update users set firstname = %s where user_id = %s",(first_name,session['username']))
		cursor.execute("update users set lastname = %s where user_id = %s",(last_name,session['username']))
		cursor.execute("update users set age = %s where user_id = %s",(age,session['username']))
		db.commit()
		print(first_name)
		print(last_name)
		print(age)
		# print(dept)
		return render_template('afteruserloggedin.html')

	return render_template('usersettings.html',form = form)

@app.route('/userlodgecomplaint', methods=['GET','POST'])
@nocache                  # lodge complaint
def userlodgecomplaint():
	form = LodgeComplaint()

	if form.validate_on_submit():
		subject = form.subject.data
		summary = form.summary.data
		result = request.form
		print(result)
		print(subject)
		print(summary)
		print(user_name)
		cursor.execute("insert into complaint values(DEFAULT,'somecat','somesubcat',%s,'0',%s,%s)",(summary,session['username'],subject))
		db.commit()
		return render_template('afteruserloggedin.html')

	return render_template('userlodgecomplaint.html',form = form)


result1 = dict()
i=0
for i in range(1,1000):
	result1[str(i)] = i+2

@app.route('/userhistory',methods = ['POST','GET'])
@nocache                          # complaint history
def userhistory():
    return render_template('userhistory.html',result = result1)

@app.route('/userresolvecomplaint')
@nocache
def userresolvecomplaint():
	result1 = dict()
	result1["dept"] = "hey"
	result1["division"] = "hello"
	result1["complaint"] = "edfvghyhbnkjhgfds "
	result1["statusquo"] = "yes"
	return render_template('userresolvecomplaint.html' , result = result1)


@app.route('/logout')
@nocache
def logout():
	session.pop('username',None)
	return redirect(url_for('base1'))


#-----------------------------------------------------------------------------------------------------------------------------------------------------#


#--------------------------------------------------------------------Admin-----------------------------------------------------------------------------#


@app.route('/admin')
@nocache                                           #login
def admin():
    return render_template('admin.html')


@app.route('/adminlogin', methods=['GET','POST'])
@nocache                            #Login
def adminlogin():
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember = form.remember.data
		session['admin'] = username
		# hashed_pass = generate_password_hash(password, "sha256")
		sql = "select password from admin where admin_id = '{0}'"
		cursor.execute(sql.format(username))
		res = cursor.fetchall()

		# print (check_password_hash(hashed_pass, password))
		print(username)
		print(password)
		print(remember)
		if(res[0][0] == str(password)):   # have to write else conditions.
			return render_template('afteradminloggedin.html')
	return render_template('adminlogin.html',form = form)


@app.route('/afteradminloggedin')
@nocache                            #Admin Page
def afteradminloggedin():
    return render_template('afteradminloggedin.html')


@app.route('/adminsettings', methods=['GET','POST'])
@nocache                    # Settings
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
		cursor.execute("update admin set name = %s where admin_id = %s",(first_name,session['admin']))
		cursor.execute("update admin set lastname = %s where admin_id = %s",(last_name,session['admin']))
		cursor.execute("update admin set age = %s where admin_id = %s",(age,session['admin']))
		db.commit()
		return render_template('afteradminloggedin.html')

	return render_template('adminsettings.html',form = form)

@app.route('/adminprofileinfo',methods = ['POST', 'GET'])
@nocache   			#Admin Profile Info
def adminprofileinfo():
	sql = "select name,lastname,age from admin where admin_id='{0}'"
	cursor.execute(sql.format(session['admin']))
	res = cursor.fetchall()
	print(session['admin'])
	if(res == []):
		print("list is empty")
	result1 = dict()
	result1["first_name"] = res[0][0]
	result1["last_name"] = res[0][1]
	result1["age"] = res[0][2]
	result1["dept"] = "dept to be decided"
	return render_template('adminprofileinfo.html',result = result1)

@app.route('/adminresolvecomplaint')
@nocache                                           #Resolve Complaint
def adminresolvecomplaint():
	result1 = dict()
	result1["dept"] = "hey"
	result1["division"] = "hello"
	result1["complaint"] = "edfvghyhbnkjhgfds geif7t,9d"
	return render_template('adminresolvecomplaint.html' , result = result1)

result1 = dict()
i=0
for i in range(1,1000):
	result1[str(i)] = i+2

@app.route('/admincomplainthistory',methods = ['POST','GET'])
@nocache		               #Admin history
def admincomplainthistory():
    return render_template('admincomplainthistory.html',result = result1)



@app.route('/logout1')
@nocache
def logout1():
	session.pop('admin',None)
	return redirect(url_for('base1'))


#--------------------------------------------------------------------------------------------------------------------------------------------------------#
#---------------------------------------------------------------------Super Admin------------------------------------------------------------------------#

@app.route('/superadmin')
@nocache
def superadmin():
    return render_template('superadmin.html')

@app.route('/superadminlogin', methods=['GET','POST'])
@nocache                            #Login
def superadminlogin():
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember = form.remember.data
		session['superuser'] = username
		# hashed_pass = generate_password_hash(password, "sha256")
		# print (check_password_hash(hashed_pass, password))
		sql = "select password from super_admin where superadmin = '{0}'"
		cursor.execute(sql.format(username))
		res = cursor.fetchall()
		print(username)
		print(password)
		print(remember)
		if res[0][0] == str(password):
			return render_template('aftersuperadminloggedin.html')
	return render_template('superadminlogin.html',form = form)

@app.route('/aftersuperadminloggedin')
@nocache
def aftersuperadminloggedin():
    return render_template('aftersuperadminloggedin.html')


@app.route('/superadmin_addadmin',methods=['GET','POST'])
@nocache
def superadmin_addadmin():
	form = AddRemoveAdmin()

	if form.validate_on_submit():
		email = form.email.data
		first_name = form.first_name.data
		last_name = form.last_name.data
		age = form.age.data
		dept = form.department.data
		division = form.division.data
		passcode = form.passcode.data
		cursor.execute("insert into admin values(%s,%s,%s,%s,%s)",(email,passcode,first_name,last_name,age))
		sql = "select * from subcat where subcategory = '{0}' and category_ref = '{1}'"
		cursor.execute(sql.format(division,dept))
		res = cursor.fetchall()
		if res!=[]:
			cursor.execute("insert into admin_cat values(%s,%s,%s)",(email,dept,division))
			db.commit()
			print(first_name)
			print(last_name)
			print(age)
			print(dept)
			print(division)
			return render_template('aftersuperadminloggedin.html')
		else:
			return("choose correct cat and subcat pair")

	return render_template('superadminaddadmin.html',form = form)

@app.route('/superadminprofileinfo',methods = ['POST', 'GET'])
@nocache
def superadminprofileinfo():
	sql = "select * from super_admin where superadmin = '{0}'"
	cursor.execute(sql.format(session['superuser']))
	res = cursor.fetchall()
	result1 = dict()
	result1["first_name"] = res[0][2]
	result1["last_name"] = "to be added to database"
	result1["age"] = "to be added "
	result1["dept"] = "to be added to databse"
	return render_template('superadminprofileinfo.html',result = result1)

@app.route('/superadmin_removeadmin',methods=['GET','POST'])
@nocache
def superadmin_removeadmin():
	form = RemoveAdmin()

	if form.validate_on_submit():
		adminemail = form.adminemail.data
		# first_name = form.first_name.data
		# last_name = form.last_name.data
		# age = form.age.data
		# dept = form.department.data
		# division = form.division.data
		# print(first_name)
		# print(last_name)
		# print(age)
		# print(dept)
		# print(division)
		sql = "select admin_id from admin where admin_id = '{0}'"
		cursor.execute(sql.format(adminemail))
		res = cursor.fetchall()
		if(res!=[]):
			sql = "delete from admin where admin_id = '{0}'"
			cursor.execute(sql.format(adminemail))
			db.commit()
			return render_template('aftersuperadminloggedin.html')
		else:
			return("enter correct admin email")

	return render_template('superadminremoveadmin.html',form = form)

@app.route('/superadmin_adddivision', methods =['GET','POST'])
@nocache
def superadmin_adddivision():
	form = AddRemoveDivision()

	if form.validate_on_submit():
		dept = form.department.data
		division = form.division.data
		print(dept)
		print(division)
		sql = "select * from cat where category = '{0}'"
		cursor.execute(sql.format(dept))
		res = cursor.fetchall()
		if(res!=[]):
			sql = "select * from subcat where category_ref = '{0}' and subcategory='{1}'"
			cursor.execute(sql.format(dept,division))
			res1 = cursor.fetchall()
			if(res1==[]):
				cursor.execute("insert into subcat values(%s,%s)",(division,dept))
				db.commit()
				return render_template('aftersuperadminloggedin.html')
			else:
				return("already pair exists")
		else:
			return("no such category exists")


	return render_template('superadminadddivision.html', form=form)

@app.route('/superadmin_removedivision',methods=['GET','POST'])
@nocache
def superadmin_removedivision():
	form = AddRemoveDivision()

	if form.validate_on_submit():
		dept = form.department.data
		division = form.division.data
		print(dept)
		print(division)
		sql = "select * from cat where category = '{0}'"
		cursor.execute(sql.format(dept))
		res = cursor.fetchall()
		if(res!=[]):
			sql = "select * from subcat where category_ref = '{0}' and subcategory='{1}'"
			cursor.execute(sql.format(dept,division))
			res1 = cursor.fetchall()
			if(res1!=[]):
				# cursor.execute("insert into subcat values(%s,%s)",(dept,division))
				sql1 = "delete from subcat where subcategory = '{0}' and category_ref = '{1}'"
				cursor.execute(sql1.format(division,dept))
				db.commit()
				return render_template('aftersuperadminloggedin.html')
			else:
				return("that pair donot exist")
		else:
			return("no such category exists")



	return render_template('superadminremovedivision.html',form=form)

@app.route('/superadmin_adddepartment',methods=['GET','POST'])
@nocache
def superadmin_adddepartment():
	form = AddRemoveDepartment()

	if form.validate_on_submit():
		dept = form.department.data
		print(dept)
		sql = "select * from cat where category = '{0}'"
		cursor.execute(sql.format(dept))
		res = cursor.fetchall()
		if(res!=[]):
			return("already category  exists")

		else:
			cursor.execute("insert into cat values(%s)",(dept))
			db.commit()
			return render_template('aftersuperadminloggedin.html')



	return render_template('superadminadddepartment.html',form=form)


@app.route('/superadmin_removedepartment', methods=['GET','POST'])
@nocache
def superadmin_removedepartment():
	form = AddRemoveDepartment()

	if form.validate_on_submit():
		dept = form.department.data
		print(dept)
		sql = "select * from cat where category = '{0}'"
		cursor.execute(sql.format(dept))
		res = cursor.fetchall()
		if(res!=[]):
			sql1 = "delete from subcat where category_ref"
			sql1 = "delete from cat where category = '{0}'"
			cursor.execute(sql1.format(dept))
			db.commit()
			return render_template('aftersuperadminloggedin.html')
		else:
			return("no such category  exists")


	return render_template('superadminremovedepartment.html',form=form)

@app.route('/superadminsettings', methods=['GET','POST'])
@nocache
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

@app.route('/logout2')
@nocache
def logout2():
	session.pop('superadmin',None)
	return redirect(url_for('base1'))


#---------------------------------------------------------------------------------------------------------------------------------------------------------#







@app.route('/dashboard')
def dashboard():
	return render_template('dashboard.html')


if __name__ == '__main__':
	app.run(debug=True)

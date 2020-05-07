from flask import Flask,render_template,request,session,redirect,url_for,flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField,IntegerField, TextField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
from app import app, cursor, db

app = Flask(__name__)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'noreply.cms1234@gmail.com'
app.config['MAIL_PASSWORD'] = 'CMS@1234'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SECRET_KEY'] = 'Secret!'
mail = Mail(app)
Bootstrap(app)

s = URLSafeTimedSerializer('Secret!')

class LoginForm(FlaskForm):
	username = StringField('username',validators=[InputRequired(),Email(message='Invalid email'), Length(max=50 )])
	password = PasswordField('password',validators=[InputRequired(), Length(min=4, max=80)])
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

class ChangePassword(FlaskForm):
	new_password = PasswordField('New Password',validators=[InputRequired(), Length(min=8, max=80)])
	confirm_new = PasswordField('Confirm New Password',validators=[InputRequired(), Length(min=8, max=80)])
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
	# category = SelectField('category',coerce = str,choices=[])
	subcategory = SelectField('subcategory',validators = [InputRequired()],coerce = str,choices=[])
	subject = TextField('Subject of the complaint', validators=[InputRequired()])
	summary = TextField('Write Your Complaint', validators=[InputRequired(), Length(min=5)])


class AddRemoveAdmin(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	first_name = StringField('First Name',validators=[InputRequired(), Length(min=3, max=20)])
	last_name = StringField('Last Name',validators=[InputRequired(), Length(min=3, max=20)])
	age = IntegerField('Age',validators=[InputRequired()])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])
	passcode = PasswordField('passcode',validators=[InputRequired(),Length(min=8,max=20)])

class AddRemoveDivision(FlaskForm):
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])

class AddRemoveDepartment(FlaskForm):
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])

class RemoveAdmin(FlaskForm):
	adminemail = StringField('adminemail', validators=[InputRequired(), Length(max=30)])
	department = StringField('Department', validators=[InputRequired(), Length(max=30)])
	division = StringField('Division',validators=[InputRequired()])

class DynamicDropdown(FlaskForm):
	department = StringField('department',choices=[('a','a'),('b','b')])
	division = StringField('division',choices=[])


#-------------------------------------------- -------------------Initial Page---------------------------------------------------------------------------#

@app.route('/')
#@nocache
def base1():
    session['username']=""
    session['admin']=""
    session['superuser']=""
    return render_template('base1.html')

#------------------------------------------------------------------User--------------------------------------------------------------------------------#

@app.route('/user')
#@nocache                                             #login page
def user():
	session['username']=" "
	return render_template('user.html')

@app.route('/signup', methods=['GET', 'POST'])
#@nocache                       #Signup
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        userres = dict()
        userres["email"] = form.email.data
        userres["password"] = generate_password_hash(form.password.data, "sha256") #converts password into it's hash
        userres["firstname"] = form.firstname.data
        userres["lastname"]  = form.lastname.data
        userres["age"] = form.age.data
        email = userres["email"]
        sql = "select user_id,password from users where user_id = '{0}'"
        cursor.execute(sql.format(userres["email"]))
        res = cursor.fetchall()
        print(len(res))
        if(res==[]):
            user_name = email
            token = s.dumps(userres,salt = 'email-confirm')
            msg = Message('Confirm Email',sender = 'noreply.cms1234@gmail.com',recipients = [email])
            link = url_for('confirm_email',token = token, _external = True)
            msg.body = 'Link is valid for only 10 minutes \n Your link is {}'.format(link)
            mail.send(msg)
            return '<h1> Please goto your mail and confirm your email</h1> <br/><h2> It may take five minutes to receive mail </h2>'
        else:
            session.pop('_flashes', None)
            flash("User already exists. Login to continue",'warning')
            return redirect(url_for('userlogin'))
    return render_template('signup.html',form = form)

@app.route('/confirm_email/<token>')
def confirm_email(token):
	try:
		user_d = s.loads(token,salt = 'email-confirm',max_age = 600)
		print(user_d)
		cursor.execute("insert into users values(%s,%s,%s,%s,%s)",(user_d["email"],user_d["password"],user_d["firstname"],user_d["lastname"],user_d["age"]))
		session['username'] = user_d["email"]
		db.commit()
		session.pop('_flashes', None)
		flash("Successfully signed up",'success')
	except:
		# sql = "delete from users where user_id = '{0}'"
		# cursor.execute(sql.format(session['username']))
		# db.commit()
		print("errors")

		return '<h1> The link is expired </h1>'
	return render_template('afteruserloggedin.html')

@app.route('/userlogin', methods=['GET','POST'])
#@nocache                              #Login
def userlogin():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.datuser_name = username
        sql = "select user_id,password from users where user_id = '{0}'"
        cursor.execute(sql.format(username))
        res = cursor.fetchall()
        if(res==[]):
            session.pop('_flashes', None)
            flash("Invalid Username",'danger')
            return redirect(url_for('userlogin'))
        else:
            if check_password_hash(str(res[0][1]), password):
                 session['username'] = username
                 session.pop('_flashes', None)
                 flash("Successfully Loggedin",'success')
                 return render_template('afteruserloggedin.html')
            else :
                session.pop('_flashes', None)
                flash("Incorrect password",'danger')
                return redirect(url_for('userlogin'))
    return render_template('userlogin.html',form = form)


@app.route('/afteruserloggedin',methods = ['POST', 'GET'])
#@nocache                               #user page
def afteruserloggedin():
    if (session['username']!=""):
        username = session['username']
        return render_template('afteruserloggedin.html')
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('userlogin'))


@app.route('/userprofileinfo',methods = ['POST', 'GET'])
#@nocache      #user profile info
def userprofileinfo():
    if (session['username']!=""):
    	username = session['username']
    	sql = "select firstname,lastname,age from users where user_id = '{0}'"
    	try:
    		cursor.execute(sql.format(session['username']))
    		resultx = cursor.fetchall()
    		result1 = dict()
    		result1["first_name"] = resultx[0][0]
    		result1["last_name"] = resultx[0][1]
    		result1["age"] = resultx[0][2]
    		result1["dept"] = "dept"
    		return render_template('userprofileinfo.html',result = result1)
    	except:
    		print("errors")
    else :
    	session.pop('_flashes', None)
    	flash("Warning : This action is prevented before login. Please, login",'danger')
    	return redirect(url_for('userlogin'))


@app.route('/usersettings', methods=['GET','POST'])
#@nocache                 #user settings
def usersettings():
    if (session['username']!=""):

        form = UserProfile()

        if form.validate_on_submit():
            first_name = form.first_name.data
            last_name = form.last_name.data
            age = form.age.data
            try:
            	cursor.execute("update users set firstname = %s where user_id = %s",(first_name,session['username']))
            	cursor.execute("update users set lastname = %s where user_id = %s",(last_name,session['username']))
            	cursor.execute("update users set age = %s where user_id = %s",(age,session['username']))
            	db.commit()
            	return render_template('afteruserloggedin.html')
            except:
            	print("errors")
        return render_template('usersettings.html',form = form)
    else :
    	session.pop('_flashes', None)
    	flash("Warning : This action is prevented before login. Please, login",'danger')
    	return redirect(url_for('userlogin'))


@app.route('/userchangepassword', methods=['GET','POST'])
#@nocache                 #user settings
def userchangepassword():
    if (session['username']!=""):

        form = ChangePassword()

        if form.validate_on_submit():
            new_password = form.new_password.data
            confirm_new = form.confirm_new.data
            # dept =  form.department.data
            if(new_password==confirm_new):
                new_password = generate_password_hash(new_password, "sha256") #converts password into it's hash
                try:
                    cursor.execute("update users set password = %s where user_id = %s",(new_password,session['username']))
                    db.commit()
                    print(new_password)
                    msg = Message('Password Change request', sender = 'noreply.cms1234@gmail.com', recipients = [session['username']])
                    msg.body =  "your password is changed \n "
                    mail.send(msg)
                    # print(dept)
                    session.pop('_flashes', None)
                    flash("Password Changed",'success')
                except:
                    print("something  to terminal")
                return render_template('afteruserloggedin.html')
            else :
                session.pop('_flashes', None)
                flash("Entered passwords don't match",'warning')
                return redirect(url_for('userchangepassword'))

        return render_template('userchangepassword.html',form = form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('userlogin'))

@app.route('/userlodgecomplaint1',methods=['POST','GET'])
def userlodgecomplaint1():
    if (session['username']!=""):
        sql = "select distinct category_ref from admin_cat"
        try:
            cursor.execute(sql)
            result = cursor.fetchall()
            if(result==[]) :
                session.pop('_flashes',None)
                flash("Working on admins. Please try after sometime",'warning')
                return redirect(url_for('afteruserloggedin'))
            else :
                return render_template('userlodgecomplaint1.html',result = result)
        except:
        	print("erros")
    else :
    	session.pop('_flashes', None)
    	flash("Warning : This action is prevented before login. Please, login",'danger')
    	return redirect(url_for('userlogin'))


@app.route('/userlodgecomplaint2',methods=['POST','GET'])
def userlodgecomplaint2():
    if (session['username']!=""):

        var1 = request.form.get('dept')
        print(var1)
        sql = "select distinct subcategory_ref from admin_cat where category_ref = '{0}' "    #query for subcat fetching
        cursor.execute(sql.format(var1))
        result = cursor.fetchall()
        res_dic = []
        for i in range(len(result)):
            element = (str(i+1),str(result[i][0]))
            res_dic.append(element)
        print(res_dic)
        return render_template('userlodgecomplaint2.html',result = result,value = var1)      #have to add value of sel for display here
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('userlogin'))


@app.route('/userlodgecomplaint3/<department>/', methods=['POST','GET'])
#@nocache                  # lodge complaint
def userlodgecomplaint3(department):
    if (session['username']!=""):
        variable2 = request.form.get('subcategory')
        department = str(department)
        print(variable2)
        print(department)
        return render_template('userlodgecomplaint3.html',val=department,val1 = variable2)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('userlogin'))

@app.route('/complaintsubmitted/<dept>/<div1>',methods = ['GET','POST'])
def complaintsubmitted(dept,div1):
	if (session['username']!=""):
		category = str(dept)
		subcategory = str(div1)
		subject = request.form.get('subject')
		print(subject)
		summary = request.form.get('summary')
		status  = "lodge_complaint"
		try:
			cursor.execute("insert into complaint(category_ref,subcat_ref,complaint,status,user_id_ref,subject) values(%s,%s,%s,%s,%s,%s)",(category,subcategory,summary,status,session['username'],subject))
			db.commit()
			sql = "select admin_ref from admin_cat where category_ref = '{0}' and subcategory_ref = '{1}'"
			cursor.execute(sql.format(category,subcategory))
			res = cursor.fetchall()
			admin = res[0][0]
			print(subject)
			msg = Message(subject, sender = 'noreply.cms1234@gmail.com', recipients = [admin])
			msg.body =  summary
			mail.send(msg)
			session.pop('_flashes', None)
			flash("Success : Complaint Lodged",'success')
			return redirect(url_for('afteruserloggedin'))
		except:
			print("databse is good")
			return redirect(url_for('afteruserloggedin'))
	else :
		session.pop('_flashes', None)
		flash("Warning : This action is prevented before login. Please, login",'danger')
		return redirect(url_for('userlogin'))


@app.route('/userhistory',methods = ['POST','GET'])
#@nocache                          # complaint history
def userhistory():
    if (session['username']!=""):
        statres = "lodge_complaint"
        sql = "select complaint_id,complaint,status,category_ref,subcat_ref,subject from complaint where user_id_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['username'],statres))
        result1 = cursor.fetchall()
        print(result1)
        statres1 = "adminresponded"
        sql = "select complaint_id,complaint,status,category_ref,subcat_ref,subject from complaint where user_id_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['username'],statres1))
        x = cursor.fetchall()

        statres2 = "userresponded_un"
        sql = "select complaint_id,complaint,status,category_ref,subcat_ref,subject from complaint where user_id_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['username'],statres2))
        y = cursor.fetchall()

        statres3 = "userresponded_s"
        sql = "select complaint_id,complaint,status,category_ref,subcat_ref,subject from complaint where user_id_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['username'],statres3))
        z = cursor.fetchall()
        return render_template('userhistory.html',result = result1,resultx = x,resulty = y,resultz = z)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('userlogin'))

@app.route('/userresolvecomplaint/<cid>')
#@nocache
def userresolvecomplaint(cid):
    if (session['username']!=""):

        result1 = dict()
        cid = int(cid)
        try:
            sql = "select category_ref,subcat_ref,complaint,status from complaint where complaint_id = '{0}'"
            cursor.execute(sql.format(cid))
            res = cursor.fetchall()
            result1["dept"] = res[0][0]
            result1["division"] = res[0][1]
            result1["complaint"] = res[0][2]
            result1["cid"] = cid
            if res[0][3] == "lodge_complaint":
                result1["statusquoadmin"] = "None"
                return render_template('userseeingadminstatus.html' , result = result1)
            elif res[0][3] == "adminresponded":
                result1["statusquoadmin"] = "Resolved"
                return render_template('userresolvecomplaint.html',result = result1)
                # userres = request.form.get('statususer')

                print(userres)
                return("have to redirect page")
            elif res[0][3] == "userresponded_un":
                result1["statusquouser"] = "Un-satisfactory"
                result1["statusquoadmin"] = "Resolved"
                return render_template('usersentfeedback.html' , result = result1)
            else:
                result1["statusquouser"] = "Satisfactory"
                result1["statusquoadmin"] = "Resolved"
                return render_template('usersentfeedback.html' , result = result1)

        except:
            cursor.rollback()
            print("check for error")
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('userlogin'))

@app.route('/userchangestatus/<cid>',methods = ['POST','GET'])

def userchangestatus(cid):
    if request.method == "POST":
        userres = request.form.get('statususer')
        print(userres)
        if userres =="Satisfactory":
            statusres = "userresponded_s"
        else:
            statusres = "userresponded_un"
        try:
            cursor.execute("update complaint set status = %s where complaint_id = %s",(statusres,cid))
            db.commit()
            sql = "select category_ref,subcat_ref from complaint where complaint_id = '{0}'"
            cursor.execute(sql.format(cid))
            res = cursor.fetchall()
            sql1 = "select admin_ref from admin_cat where category_ref = '{0}' and subcategory_ref = '{1}'"
            cursor.execute(sql1.format(res[0][0],res[0][1]))
            res1 = cursor.fetchall()
            msg = Message('user feed back', sender = 'noreply.cms1234@gmail.com', recipients = [res1[0][0]])
            msg.body =  " user reviewed the complaint with complaintid = {} ".format(cid)
            mail.send(msg)
        except:
            print("errors")

        return redirect(url_for('userhistory'))



@app.route('/logout')
##@nocache
def logout():
	session.pop('username',None)
	return redirect(url_for('base1'))


#-----------------------------------------------------------------------------------------------------------------------------------------------------#


#--------------------------------------------------------------------Admin-----------------------------------------------------------------------------#


@app.route('/admin')
##@nocache                                           #login
def admin():
	session['admin'] = ""
	return render_template('admin.html')


@app.route('/adminlogin', methods=['GET','POST'])
#@nocache                            #Login
def adminlogin():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data
        sql = "select password from admin where admin_id = '{0}'"
        cursor.execute(sql.format(username))
        res = cursor.fetchall()
        if(res==[]):
            session.pop('_flashes', None)
            flash("Invalid Admin Id",'danger')
            return redirect(url_for('adminlogin'))
        else :
            if check_password_hash(res[0][0], password):
                session['admin'] = username
                session.pop('_flashes', None)
                flash("Successfully Loggedin",'success')    # have to write else conditions.
                return render_template('afteradminloggedin.html')
            else :
                session.pop('_flashes', None)
                flash("Incorrect Password",'danger')    # have to write else conditions.
                return render_template('adminlogin.html',form=form)
    return render_template('adminlogin.html',form = form)


@app.route('/afteradminloggedin')
#@nocache                            #Admin Page
def afteradminloggedin():
    if (session['admin']!=""):
        return render_template('afteradminloggedin.html')
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('adminlogin'))


@app.route('/adminsettings', methods=['GET','POST'])
#@nocache                    # Settings
def adminsettings():
    if (session['admin']!=""):

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
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('adminlogin'))


@app.route('/adminprofileinfo',methods = ['POST', 'GET'])
#@nocache   			#Admin Profile Info
def adminprofileinfo():
    if (session['admin']!=""):

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
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('adminlogin'))

@app.route('/adminchangepassword', methods=['GET','POST'])
#@nocache                 #user settings
def adminchangepassword():
    if (session['admin']!=""):

        form = ChangePassword()

        if form.validate_on_submit():
            new_password = form.new_password.data
            confirm_new = form.confirm_new.data

            # dept =  form.department.data
            if(new_password==confirm_new):
                new_password= generate_password_hash(new_password, "sha256") #converts password into it's hash
                try:
                    cursor.execute("update admin set password = %s where admin_id = %s",(new_password,session['admin']))
                    db.commit()
                    msg = Message('Password Change request', sender = 'noreply.cms1234@gmail.com', recipients = [session['username']])
                    msg.body =  "your password is changed \n "
                    mail.send(msg)
                    print(new_password)
                except:
                    print("errors")
                # print(dept)
                session.pop('_flashes',None)
                flash("Password Changed",'success')
                return render_template('afteradminloggedin.html')
            else :
                session.pop('_flashes', None)
                flash("Entered passwords don't match",'warning')
                return redirect(url_for('adminchangepassword'))

        return render_template('adminchangepassword.html',form = form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('adminlogin'))

@app.route('/adminresolvecomplaint/<cid>')
#@nocache                                           #Resolve Complaint
def adminresolvecomplaint(cid):
    if (session['admin']!=""):
        result1 = dict()
        cid = int(cid)
        try:
            sql = "select category_ref,subcat_ref,complaint,status from complaint where complaint_id = '{0}'"
            cursor.execute(sql.format(cid))
            res = cursor.fetchall()
            result1["dept"] = res[0][0]
            result1["division"] = res[0][1]
            result1["complaint"] = res[0][2]
            result1["cid"] = cid
            if res[0][3] == "lodge_complaint":
                # adminres = request.form.get("statusadmin")
                # print(adminres)
                # insert statement here
                return render_template("adminresolvecomplaint.html" , result = result1)

            elif res[0][3] == "userresponded_un":
                result1["statusquouser"] = "Not Satisfied"
                result1["statusquoadmin"] = "Responded"
                return render_template("adminupdatedstatus.html" , result = result1)
            elif res[0][3] == "adminresponded":
                result1["statusquouser"] = "Not Reviewed"
                result1["statusquoadmin"] = "Responded"
                return render_template("adminupdatedstatus.html" , result = result1)
            else:
                result1["statusquouser"] = "Satisfied"
                result1["statusquoadmin"] = "Responded"
                return render_template("adminupdatedstatus.html" , result = result1)


        except:
            # cursor.rollback()
            print("admin error db")
        return render_template('adminresolvecomplaint.html' , result = result1)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('adminlogin'))

@app.route('/adminchangestatus/<cid>',methods =['POST','GET'])

def adminchangestatus(cid):
    if request.method == 'POST':
        userres = request.form.get('statusadmin')
        print("hello to tyou brothert")
        if(userres == "Resolved"):
            statusres = "adminresponded"
            print(statusres)
            print(cid)
            try:
                cursor.execute("update complaint set status = %s where complaint_id = %s",(statusres,cid))
                db.commit()
                sql = "select user_id_ref from complaint where complaint_id = '{0}'"
                cursor.execute(sql.format(cid))
                res = cursor.fetchall()
                msg = Message('admin resolved complainted', sender = 'noreply.cms1234@gmail.com', recipients = [res[0][0]])
                msg.body =  "your complaint  with complaint id: {}is resolved, Please check and review regarding the same \n ".format(cid)
                mail.send(msg)
                print(userres)
            except:
                print("errors")
            return redirect(url_for('admincomplainthistory'))
    return redirect(url_for('admincomplainthistory'))



@app.route('/admincomplainthistory',methods = ['POST','GET'])
#@nocache		               #Admin history
def admincomplainthistory():
    if (session['admin']!=""):
        statres = "lodge_complaint"
        sql = "select complaint_id,complaint,status,complaint.category_ref,subcat_ref,subject from admin_cat INNER JOIN complaint  ON (admin_cat.category_ref = complaint.category_ref AND admin_cat.subcategory_ref = complaint.subcat_ref)where admin_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['admin'],statres))
        result1 = cursor.fetchall()
        print(result1)
        statres1 = "adminresponded"
        sql = "select complaint_id,complaint,status,complaint.category_ref,subcat_ref,subject from admin_cat INNER JOIN complaint  ON (admin_cat.category_ref = complaint.category_ref AND admin_cat.subcategory_ref = complaint.subcat_ref)where admin_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['admin'],statres1))
        x = cursor.fetchall()
        statres2 = "userresponded_un"
        sql = "select complaint_id,complaint,status,complaint.category_ref,subcat_ref,subject from admin_cat INNER JOIN complaint  ON (admin_cat.category_ref = complaint.category_ref AND admin_cat.subcategory_ref = complaint.subcat_ref)where admin_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['admin'],statres2))
        y = cursor.fetchall()
        statres3 = "userresponded_s"
        sql = "select complaint_id,complaint,status,complaint.category_ref,subcat_ref,subject from admin_cat INNER JOIN complaint  ON (admin_cat.category_ref = complaint.category_ref AND admin_cat.subcategory_ref = complaint.subcat_ref)where admin_ref = '{0}' and status = '{1}'"
        cursor.execute(sql.format(session['admin'],statres3))
        z = cursor.fetchall()
        print(result1)
        return render_template('admincomplainthistory.html',result = result1,resultx = x,resulty = y,resultz = z)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('adminlogin'))



@app.route('/logout1')
#@nocache
def logout1():
	session.pop('admin',None)
	return redirect(url_for('base1'))

#--------------------------------------------------------------------------------------------------------------------------------------------------------#
#---------------------------------------------------------------------Super Admin------------------------------------------------------------------------#

@app.route('/superadmin')
#@nocache
def superadmin():
	session['superuser'] = " "
	return render_template('superadmin.html')

@app.route('/superadminlogin', methods=['GET','POST'])
#@nocache                            #Login
def superadminlogin():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data
		# hashed_pass = generate_password_hash(password, "sha256")
		# print (check_password_hash(hashed_pass, password))
        sql = "select password from super_admin where superadmin = '{0}'"
        cursor.execute(sql.format(username))
        res = cursor.fetchall()
        if(res==[]) :
            session.pop('_flashes', None)
            flash("Invalid SuperAdmin Id",'danger')
            render_template('superadminlogin.html',form=form)
        else :

            if check_password_hash(res[0][0],password):
                session['superuser'] = username

                session.pop('_flashes', None)
                flash("Successfully Loggedin",'success')
                return render_template('aftersuperadminloggedin.html')
            else :
                session.pop('_flashes', None)
                flash("Incorrect password",'danger')
                render_template('superadminlogin.html',form=form)
    return render_template('superadminlogin.html',form = form)

@app.route('/aftersuperadminloggedin')
#@nocache
def aftersuperadminloggedin():
    if (session['superuser']!=""):
        return render_template('aftersuperadminloggedin.html')
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))


@app.route('/superadmin_addadmin',methods=['GET','POST'])
#@nocache
def superadmin_addadmin():
    if (session['superuser']!=""):
        form = AddRemoveAdmin()
        if form.validate_on_submit():
            email = form.email.data
            first_name = form.first_name.data
            last_name = form.last_name.data
            age = form.age.data
            dept = form.department.data
            division = form.division.data
            passcode = form.passcode.data
            passcode = generate_password_hash(passcode,"sha256")
            sql = "select * from subcat where subcategory = '{0}' and category_ref = '{1}'"
            sql1 = "select * from admin where admin_id = '{0}'"
            try:
                cursor.execute(sql.format(division,dept))
                res = cursor.fetchall()
                cursor.execute(sql1.format(email))
                res1 = cursor.fetchall()
                if res!=[]:
                    if res1 == []:
                        cursor.execute("insert into admin values(%s,%s,%s,%s,%s)",(email,passcode,first_name,last_name,age))
                    cursor.execute("insert into admin_cat values(%s,%s,%s)",(email,dept,division))
                    db.commit()
                    return render_template('aftersuperadminloggedin.html')
                else:
                    session.pop('_flashes', None)
                    flash("Warning : The pair department and division does not exist, please enter the correct details.",'warning')
                    return redirect(url_for('superadmin_addadmin'))
            except:
                print("some database error")
        return render_template('superadminaddadmin.html',form = form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))


@app.route('/superadminprofileinfo',methods = ['POST', 'GET'])
#@nocache
def superadminprofileinfo():
    if (session['superuser']!=""):
        sql = "select * from super_admin where superadmin = '{0}'"
        cursor.execute(sql.format(session['superuser']))
        res = cursor.fetchall()
        result1 = dict()
        result1["first_name"] = res[0][2]
        result1["last_name"] = res[0][3]
        result1["age"] = res[0][4]
        return render_template('superadminprofileinfo.html',result = result1)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))

@app.route('/superadminchangepassword', methods=['GET','POST'])
#@nocache                 #user settings
def superadminchangepassword():
    if (session['superuser']!=""):

        form = ChangePassword()

        if form.validate_on_submit():
            new_password = form.new_password.data
            confirm_new = form.confirm_new.data
            # dept =  form.department.data
            if(new_password==confirm_new):
                new_password = generate_password_hash(new_password, "sha256") #converts password into it's hash
                try:
                    cursor.execute("update super_admin set password = %s where superadmin = %s",(new_password,session['superuser']))
                    db.commit()
                    print(new_password)
                except:
                    print("error may happen bro")
                # print(dept)
                return render_template('aftersuperadminloggedin.html')
            else :
                session.pop('_flashes', None)
                flash("Entered passwords don't match",'warning')
                return redirect(url_for('superadminchangepassword'))

        return render_template('superadminchangepassword.html',form = form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))


@app.route('/superadmin_removeadmin',methods=['GET','POST'])
#@nocache
def superadmin_removeadmin():
	if (session['superuser']!=""):
		form = RemoveAdmin()
		if form.validate_on_submit():
			adminemail = form.adminemail.data
			dept = form.department.data
			division = form.division.data
			sql1 = "select * from admin_cat where admin_ref = '{0}' and category_ref = '{1}' and subcategory_ref = '{2}'"
			cursor.execute(sql1.format(adminemail,dept,division))
			res1 = cursor.fetchall()
			if res1 != []:
				sql = "delete from admin_cat where admin_ref = '{0}' and category_ref = '{1}' and subcategory_ref = '{2}'"
				cursor.execute(sql.format(adminemail,dept,division))
				db.commit()
				sql1 = "select * from admin_cat where admin_ref = '{0}'"
				cursor.execute(sql1.format(adminemail))
				res = cursor.fetchall()
				if res == []:
					sql2 = "delete from admin where admin_id = '{0}'"
					cursor.execute(sql2.format(adminemail))
					db.commit()
				return render_template('aftersuperadminloggedin.html')
			else:
				session.pop('_flashes', None)
				flash("Entered details are mismatched",'warning')
				return redirect(url_for('superadmin_removeadmin'))
		return render_template('superadminremoveadmin.html',form = form)
	else :
		session.pop('_flashes', None)
		flash("Warning : This action is prevented before login. Please, login",'danger')
		return redirect(url_for('superadminlogin'))


@app.route('/superadmin_adddivision', methods =['GET','POST'])
#@nocache
def superadmin_adddivision():
    if (session['superuser']!=""):
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
                    try:
                        cursor.execute("insert into subcat values(%s,%s)",(division,dept))
                        db.commit()
                    except:
                        print("errors undochu  emo")
                    return render_template('aftersuperadminloggedin.html')
                else:
                    session.pop('_flashes', None)
                    flash(" The department and division pair already exists",'warning')
                    return redirect(url_for('superadmin_adddivision'))
            else:
                session.pop('_flashes', None)
                flash("No such department exists",'warning')
                return redirect(url_for('superadmin_adddivision'))


        return render_template('superadminadddivision.html', form=form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))

@app.route('/superadmin_removedivision',methods=['GET','POST'])
#@nocache
def superadmin_removedivision():
    if (session['superuser']!=""):

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
                    session.pop('_flashes', None)
                    flash(" The Department and Division pair doesnot exists",'warning')
                    return redirect(url_for('superadmin_removedivision'))
            else:
                session.pop('_flashes', None)
                flash(" No such department exists",'warning')
                return redirect(url_for('superadmin_removedivision'))

        return render_template('superadminremovedivision.html',form=form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))


@app.route('/superadmin_adddepartment',methods=['GET','POST'])
#@nocache
def superadmin_adddepartment():
    if (session['superuser']!=""):

        form = AddRemoveDepartment()

        if form.validate_on_submit():
            dept = form.department.data
            print(dept)
            sql = "select * from cat where category = '{0}'"
            cursor.execute(sql.format(dept))
            res = cursor.fetchall()
            if(res!=[]):
                session.pop('_flashes', None)
                flash("Department already exists",category = 'warning')
                return redirect(url_for('superadmin_adddepartment'))
            else:
                try:
                    cursor.execute("insert into cat values(%s)",(dept))
                    db.commit()
                except:
                    print("errors")

                return render_template('aftersuperadminloggedin.html')

        return render_template('superadminadddepartment.html',form=form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))


@app.route('/superadmin_removedepartment', methods=['GET','POST'])
#@nocache
def superadmin_removedepartment():
    if (session['superuser']!=""):
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
                session.pop('_flashes', None)
                flash("No such department exists",'warning')
                return redirect(url_for('superadmin_removedepartment'))


        return render_template('superadminremovedepartment.html',form=form)
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))

@app.route('/superadminsettings', methods=['GET','POST'])
#@nocache
def superadminsettings():
    if (session['superuser']!=""):
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
    else :
        session.pop('_flashes', None)
        flash("Warning : This action is prevented before login. Please, login",'danger')
        return redirect(url_for('superadminlogin'))

@app.route('/display_deptwise_heads')
def display_deptwise_heads():
	if (session['superuser']!=""):
		sql = "select subcat.category_ref,subcat.subcategory,admin_ref from subcat left join admin_cat on(admin_cat.category_ref = subcat.category_ref and admin_cat.subcategory_ref = subcat.subcategory)"
		cursor.execute(sql)
		result = cursor.fetchall()
		sql1 = "select * from cat"
		cursor.execute(sql1)
		x = cursor.fetchall()
		return render_template('show_dept_heads.html',result = result,resultx = x)
	else :
		session.pop('_flashes', None)
		flash("Warning : This action is prevented before login. Please, login",'danger')
		return redirect(url_for('adminlogin'))


@app.route('/logout2')
#@nocache
def logout2():
	session.pop('superadmin',None)
	return redirect(url_for('base1'))


#---------------------------------------------------------------------------------------------------------------------------------------------------------#





@app.route('/dashboard')
def dashboard():
	return render_template('dashboard.html')


if __name__ == '__main__':
	app.run(debug=True,threaded =True,host = '0.0.0.0')

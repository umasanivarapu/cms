from flask import Flask, render_template
app = Flask(__name__)

@app.route('/')
def base1():
    return render_template('base1.html')
		
@app.route('/user')
def user():
    return render_template('user.html')
    
@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/afteruserloggedin')
def afteruserloggedin():
    return render_template('afteruserloggedin.html')
    
@app.route('/userlodgecomplaint')
def userlodgecomplaint():
    return render_template('userlodgecomplaint.html')

@app.route('/userhistory')
def userhistory():
    return render_template('userhistory.html')

@app.route('/usersettings')
def usersettings():
    return render_template('usersettings.html')
    
@app.route('/afteradminloggedin')
def afteradminloggedin():
    return render_template('afteradminloggedin.html')
    
@app.route('/adminsettings')
def adminsettings():
    return render_template('adminsettings.html')
@app.route('/adminhistory')
def adminhistory():
    return render_template('adminhistory.html')

@app.route('/superadmin')
def superadmin():
    return render_template('superadmin.html')

@app.route('/aftersuperadminloggedin')
def aftersuperadminloggedin():
    return render_template('aftersuperadminloggedin.html')

if __name__ == '__main__':
   app.run(debug = True)
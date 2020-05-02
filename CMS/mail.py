from flask import Flask
from flask_mail import Mail, Message

app =Flask(__name__)
mail=Mail(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'noreply.cms1234@gmail.com'
app.config['MAIL_PASSWORD'] = 'CMS@1234'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

@app.route("/")
def index():
   msg = Message('Reg:Email Notification', sender = 'noreply.cms1234@gmail.com', recipients = ['cs16btech11015@iith.ac.in'])
   msg.body = " yaay email Notification is done.      This is auto-generated mail, Please don't reply.    hehe"
   mail.send(msg)
   return "Sent"

if __name__ == '__main__':
   app.run(debug = True)

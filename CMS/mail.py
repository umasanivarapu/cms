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
   msg = Message('Hello', sender = 'noreply.cms1234@gmail.com', recipients = ['cs16btech11016@iith.ac.in'])
   msg.body = "Hello Flask message sent from Flask-Mail"
   # mail.send(msg)
   mail.send(msg)
   return "Sent"

if __name__ == '__main__':
   app.run(debug = True)

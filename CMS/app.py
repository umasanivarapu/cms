import os, jinja2

from flask import Flask, flash, render_template, request, redirect, url_for, send_from_directory, Blueprint
# from werkzeug import secure_filename


'''Main app file where we connect to database'''
global app
app = Flask(__name__, template_folder='templates/')
app.secret_key = 'secret'



#################### connect to database ###############
#!/usr/bin/python
import psycopg2
db = psycopg2.connect(database="cms", user = "postgres", password = "postgres", host = "127.0.0.1", port = "5432")
#username for database, password, databasename
cursor = db.cursor()

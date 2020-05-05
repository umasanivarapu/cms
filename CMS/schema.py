import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

con = psycopg2.connect(host = "localhost", user="postgres", password="postgres")
con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

cursor = con.cursor()
name_database = "cms"

sqlcreate = "create database "+name_database+";"
cursor.execute(sqlcreate)
con.commit()

con = psycopg2.connect(host="localhost",database=name_database, user="postgres", password="postgres")

cursor = con.cursor()

table_create = "create table admin(admin_id text primary key,password text,name text,lastname text,age int);"
cursor.execute(table_create)

table_create = "create table cat(category text primary key);"
cursor.execute(table_create)

table_create = "create table subcat(subcategory text ,category_ref text, primary key(subcategory,category_ref),foreign key(category_ref) references cat ON DELETE CASCADE);"
cursor.execute(table_create)


table_create = "create table users(user_id text primary key,password text,firstname text,lastname text, age int);"
cursor.execute(table_create)

table_create = "create table complaint(complaint_id serial primary key,category_ref text,subcat_ref text,complaint text,status text,user_id_ref text, subject text,foreign key(subcat_ref,category_ref) references subcat(subcategory,category_ref) ON DELETE CASCADE, foreign key (user_id_ref) references users ON DELETE CASCADE);"
cursor.execute(table_create)


table_create = "create table admin_cat(admin_ref text,category_ref text,subcategory_ref text,foreign key(admin_ref) references admin ON DELETE CASCADE,foreign key(category_ref,subcategory_ref) references subcat(category_ref,subcategory) ON DELETE CASCADE);"
cursor.execute(table_create)

table_create = "create table super_admin( superadmin text primary key, password text, firstname text,lastname text,age int);"
cursor.execute(table_create)
con.commit();

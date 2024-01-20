from flask import Flask, render_template, request, redirect, url_for, flash, session

from werkzeug.utils import secure_filename

import os
from flask_login import login_required, LoginManager, login_user, UserMixin

from flask_bcrypt import Bcrypt


from functools import wraps
from datetime import date

import connect
import mysql.connector

app = Flask(__name__)
app.config['SECRET_KEY'] = 'some_random_string_here'
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, UserID, Username, UserType):
        self.id = UserID
        self.Username = Username
        self.UserType = UserType


#setup database
def getCursor():
    global dbconn
    global connection
    connection = mysql.connector.connect(user=connect.dbuser, \
    password=connect.dbpass, host=connect.dbhost, \
    database=connect.dbname, autocommit=True)
    #dbconn = connection.cursor()
    return connection.cursor(dictionary=True)

def update_Passwords():
    connection = mysql.connector.connect(
        user=connect.dbuser,
        password=connect.dbpass,
        host=connect.dbhost,
        database=connect.dbname,
        autocommit=True
    )
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT UserID, Password FROM User")
        User = cursor.fetchall()

        for user in User:
            UserID = user['UserID']
            stored_Password = user['Password']

            if not stored_Password.startswith("$2b$"):
                # Hash the Password using Flask-Bcrypt
                hashed_Password = bcrypt.generate_password_hash(stored_Password).decode('utf-8')

                # Update Password in the database
                update_query = "UPDATE User SET Password = %s WHERE UserID = %s"
                cursor.execute(update_query, (hashed_Password, UserID))
                connection.commit() 

        print("Password hashed")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        cursor.close()
        connection.close()

dbconn = None
connection = None

if __name__ == '__main__':
    update_Passwords()  # 调用更新密码函数
    app.run(debug=True)
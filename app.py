from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
import os
from flask_login import login_required, LoginManager, login_user, UserMixin
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import date, timedelta,datetime
import connect
import mysql.connector
import matplotlib.pyplot as plt
import numpy as np
import re
from PIL import Image
from dateutil.relativedelta import relativedelta
from contextlib import contextmanager
from decimal import Decimal
import random
import string
import qrcode
from io import BytesIO
import base64
from flask_apscheduler import APScheduler
import json

from flask_login import current_user



def convert_date_format(original_date):
    try:
        # 将原始日期字符串转换为datetime对象
        date_object = datetime.strptime(original_date, "%Y-%m-%d")

        # 将datetime对象格式化为新的字符串格式
        new_date_format = date_object.strftime("%d/%m/%Y")

        return new_date_format
    except ValueError:
        return "Invalid Date Format"

def resize_image(input_path, output_path, size):
    with Image.open(input_path) as img:
        img.thumbnail(size, Image.ANTIALIAS)
        img.save(output_path)


app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'some_random_string_here'
bcrypt = Bcrypt(app)

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="winnie83",
    port = "3306",
    database="magicmovie"
)
cursor = db.cursor()
#setup database
connection = None
def getCursor():
    global connection

    # 检查现有的连接是否仍然可用
    if connection is None or not connection.is_connected():
        try:
            connection = mysql.connector.connect(user=connect.dbuser,
                                                 password=connect.dbpass,
                                                 host=connect.dbhost,
                                                 database=connect.dbname,
                                                 autocommit=True)
        except mysql.connector.Error as err:
            print("Error connecting to database: ", err)
            return None  # 或者抛出异常

    return connection.cursor(dictionary=True)

login_manager = LoginManager()
login_manager.init_app(app)

ROLES = ['Customer', 'Staff', 'Manager','Admin']


scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


class User(UserMixin):
    def __init__(self, UserID, Username, UserType, CustomerID):
        self.id = UserID
        self.Username = Username
        self.UserType = UserType
        self.CustomerID= CustomerID



def UserType_required(*UserTypes):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'UserType' not in session or session['UserType'] not in UserTypes:
                flash("You do not have permission to access this page.")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


      
def calculate_dates(start_date):
    return [(start_date + timedelta(days=i)).strftime('%d/%m/%Y') for i in range(7)]



#home
@app.route('/')
def home():
    return render_template('home.html')

@app.errorhandler(404)  # or any other error status
def page_not_found(error):
    # Here you can render an error page or just redirect
    return redirect(url_for('home'))



@app.route('/dashboard_customer')
@login_required
@UserType_required('Customer')
def dashboard_customer():
    # Assume the logged-in user's ID is stored in the session
    UserID = session.get('UserID')



    # Retrieve user information from the database
    cursor = getCursor()
    cursor.execute("SELECT * FROM User WHERE UserID = %s", (UserID,))
    user_info = cursor.fetchone()

    # Get the list of rentable Movie Movies from the database
    cursor.execute("SELECT * FROM Movies")
    Movies = cursor.fetchall()


    return render_template('dashboard_customer.html', user_info=user_info, Movies=Movies)

@app.route('/dashboard_all')
@login_required  # Ensure that only logged-in User can access
@UserType_required('Admin','Manager','Staff')
def dashboard_all():
    # Assume the logged-in user's ID is stored in the session
    UserID = session.get('UserID')
    # Retrieve user information from the database
    cursor = getCursor()
    cursor.execute("SELECT * FROM User WHERE UserID = %s", (UserID,))
    user_info = cursor.fetchone()
    print(user_info)

    # Get the list of rentable Movie Movies from the database
    cursor.execute("SELECT * FROM Movies")
    Movies = cursor.fetchall()

    return render_template('dashboard_all.html', user_info=user_info, UserType=session.get('UserType'), Movies=Movies)

@app.route('/add_user/<UserType>', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def add_user(UserType):
    if request.method == 'POST':
        # 通用表单字段
        Username = request.form.get('Username')
        Password = request.form.get('Password')
        Password_hash = bcrypt.generate_password_hash(Password).decode('utf-8')

        # 检查用户名是否已存在
        cursor = getCursor()
        cursor.execute("SELECT * FROM User WHERE Username = %s", (Username,))
        if cursor.fetchone():
            flash('Username already exists, please choose a different one.')
            return redirect(url_for('add_user', UserType=UserType))

        # 插入 User 表
        cursor.execute("INSERT INTO User (Username, Password, UserType) VALUES (%s, %s, %s)", (Username, Password_hash, UserType))
        UserID = cursor.lastrowid

        # 根据用户类型插入对应的表
        if UserType == 'Customer':
            CustomerID = cursor.lastrowid 
            First_name = request.form.get('First_name')
            Last_name = request.form.get('Last_name')
            Con = request.form.get('Con')
            Birthdate = request.form.get('Birthdate')
            if not re.match(r'^\d{8,15}$', Con):
                flash('Contact number must be 8 to 15 digits long.')

            cursor.execute("INSERT INTO Customer (UserID,CustomerID, First_name, Last_name, Con, Birthdate) VALUES (%s, %s,%s, %s, %s, %s)", 
                        (UserID, CustomerID, First_name, Last_name, Con, Birthdate))
        elif UserType == 'Admin':
            Adminid = cursor.lastrowid 
            First_name = request.form.get('First_name')
            Last_name = request.form.get('Last_name')
            Con = request.form.get('Con')
            Department = request.form.get('Department')
            

            cursor.execute("INSERT INTO Admin (UserID, Adminid,First_name, Last_name, Con, Department) VALUES (%s, %s,%s, %s, %s, %s)", 
                        (UserID, Adminid,First_name, Last_name, Con, Department))

        elif UserType == 'Staff':
            StaffID = cursor.lastrowid 
            First_name = request.form.get('First_name')
            Last_name = request.form.get('Last_name')
            Con = request.form.get('Con')
            Department = request.form.get('Department')
            
                
            cursor.execute("INSERT INTO Staff (UserID, StaffID,First_name, Last_name, Con, Department) VALUES (%s,%s, %s, %s, %s, %s)", 
                        (UserID, StaffID,First_name, Last_name, Con, Department)) 
        elif UserType == 'Manager':
            Managerid = cursor.lastrowid 
            First_name = request.form.get('First_name')
            Last_name = request.form.get('Last_name')
            Con = request.form.get('Con')
            Department = request.form.get('Department')
            cursor.execute("INSERT INTO Manager (UserID, Managerid,First_name, Last_name, Con, Department) VALUES (%s,%s, %s, %s, %s, %s)", 
                            (UserID, Managerid,First_name, Last_name, Con, Department)) 
        
    
        flash(f'{UserType} added successfully.')
        next_page = request.args.get('next', 'default_route')

        # 确保 next_page 是有效的路由
        if next_page not in ['manage_staff', 'manage_customer', 'home']:
            next_page = 'home'

        return redirect(url_for(next_page))


    return render_template('add_user.html', UserType=UserType)

@app.route('/manage_user/<UserType>')
@login_required
@UserType_required('Admin','Manager')
def manage_user(UserType):
    cursor = getCursor()
    search_query = request.args.get('search')
    like_pattern = f'%{search_query}%' if search_query else None

    if UserType in ['Customer', 'Staff', 'Admin', 'Manager']:
        table = UserType
        query = f"""
            SELECT {table}.*, User.Username 
            FROM {table} 
            JOIN User ON {table}.UserID = User.UserID
        """
        if search_query:
            query += f" WHERE User.Username LIKE %s OR {table}.First_name LIKE %s OR {table}.Last_name LIKE %s"
            query += f" ORDER BY {table}.Last_name"
            cursor.execute(query, (like_pattern, like_pattern, like_pattern))
        else:
            query += f" ORDER BY {table}.Last_name"
            cursor.execute(query)
    else:
        flash('Invalid user type.')
        return redirect(url_for('dashboard'))

    users = cursor.fetchall()
    print(users)
    return render_template('manage_user.html', users=users, UserType=UserType)

@app.route('/edit_user/<UserType>/<int:id>', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def edit_user(UserType, id):
    cursor = getCursor()
    current_date = date.today().isoformat()

    if request.method == 'POST':
        # 获取表单数据
        First_name = request.form.get('First_name')
        Last_name = request.form.get('Last_name')
        Con = request.form.get('Con')
        update_values = (First_name, Last_name, Con)
        if not re.match(r'^\d{8,15}$', Con):
                flash('Contact number must be 8 to 15 digits long.')
        # 根据用户类型构建不同的更新语句
        if UserType == 'Customer':
            Birthdate = request.form.get('Birthdate')
            Birthdate = datetime.strptime(Birthdate, '%Y-%m-%d') # Adjust the format as necessary
            if Birthdate > datetime.now() - relativedelta(years=12):
                flash('You must be at least 12 years old.')
            query = "UPDATE Customer SET First_name = %s, Last_name = %s, Con = %s, Birthdate = %s WHERE CustomerID = %s"
            update_values += (Birthdate, id)
        elif UserType in ['Admin', 'Manager', 'Staff']:
            Department = request.form.get('Department')
            query = f"UPDATE {UserType} SET First_name = %s, Last_name = %s, Department = %s, Con = %s WHERE {UserType.lower()}id = %s"
            update_values += (Department, id)

        cursor.execute(query, update_values)
        connection.commit()
        flash(f'{UserType} updated successfully.')
        return redirect(url_for('manage_user', UserType=UserType))

    # 获取当前用户信息填充表单
    cursor.execute(f"SELECT * FROM {UserType} WHERE {UserType}id = %s", (id,))
    user = cursor.fetchone()
    return render_template('edit_user.html', user=user, UserType=UserType, current_date=current_date)
    
@app.route('/delete_user/<UserType>/<int:id>')
@login_required
@UserType_required('Admin','Manager')
def delete_user(UserType, id):
    cursor = getCursor()

    # 根据用户类型构建相应的 SQL 删除语句
    if UserType == 'Customer':
        cursor.execute("DELETE FROM Customer WHERE CustomerID = %s", (id,))
    elif UserType == 'Staff':
        cursor.execute("DELETE FROM Staff WHERE StaffID = %s", (id,))
    elif UserType == 'Manager':
        cursor.execute("DELETE FROM Manager WHERE Managerid = %s", (id,))
    elif UserType == 'Admin':
        cursor.execute("DELETE FROM Admin WHERE Adminid = %s", (id,))
    else:
        flash('Invalid user type.')

        return redirect(url_for('dashboard'))

    connection.commit()
    flash(f'{UserType} deleted successfully.')

    # 重定向到 manage_user 页面，附带相应的 UserType 参数
    return redirect(url_for('manage_user', UserType=UserType))

@app.route('/admin/bookings')
@login_required
@UserType_required('Admin','Manager')
def admin_bookings():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 设置每页的记录数

    cursor = getCursor()

    try:
        # 查询所有预订记录和相关的客户信息
        cursor.execute("SELECT COUNT(*) AS count FROM Bookings")
        total_records_result = cursor.fetchone()
        if total_records_result is not None:
            total_records = total_records_result['count']
        else:
            total_records = 0


        # 计算总页数
        total_pages = (total_records + per_page - 1) // per_page
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT b.BookingID, c.CustomerID, c.First_name,c.Last_name, b.TotalPrice,  m.Title AS MovieTitle,
                   s.SessionDateTime, 
                    (SELECT GROUP_CONCAT(p.PaymentMethod SEPARATOR ', ')
                    FROM PaymentInfo p
                    WHERE p.BookingID = b.BookingID
                    GROUP BY p.BookingID) AS PaymentMethod
            FROM Bookings b
            JOIN Session s ON b.SessionID = s.SessionID
            JOIN Movies m ON s.MovieID = m.MovieID
            JOIN Customer c ON b.CustomerID = c.CustomerID
            GROUP BY b.BookingID
            ORDER BY b.BookingID
            LIMIT %s OFFSET %s
        """, ( per_page, offset))
        
 
        bookings = cursor.fetchall()
        print(bookings)
    finally:
        cursor.close()

    return render_template('admin_bookings.html', bookings=bookings, page=page, total_pages=total_pages)

@app.route('/my-bookings')
@login_required
def my_bookings():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 设置每页的记录数

    cursor = getCursor()
    customer_id = current_user.CustomerID

    try:
        cursor.execute("SELECT COUNT(*) AS count FROM Bookings WHERE CustomerID = %s", (customer_id,))
        total_records_result = cursor.fetchone()
        if total_records_result is not None:
            total_records = total_records_result['count']
        else:
            total_records = 0


        # 计算总页数
        total_pages = (total_records + per_page - 1) // per_page
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT b.BookingID, c.CustomerID, c.First_name,c.Last_name, b.TotalPrice,  m.Title AS MovieTitle,
                   s.SessionDateTime, 
                    (SELECT GROUP_CONCAT(p.PaymentMethod SEPARATOR ', ')
                    FROM PaymentInfo p
                    WHERE p.BookingID = b.BookingID
                    GROUP BY p.BookingID) AS PaymentMethod
            FROM Bookings b
            JOIN Session s ON b.SessionID = s.SessionID
            JOIN Movies m ON s.MovieID = m.MovieID
            JOIN Customer c ON b.CustomerID = c.CustomerID
            WHERE b.CustomerID = %s
            GROUP BY b.BookingID
            ORDER BY b.BookingID
            LIMIT %s OFFSET %s
        """, (customer_id, per_page, offset))
        bookings = cursor.fetchall()
    finally:
        cursor.close()

    return render_template('my_bookings.html', bookings=bookings, page=page, total_pages=total_pages)



def get_ticket_info(ticket_number):
   
    cursor = getCursor()

    query = "SELECT * FROM Tickets WHERE TicketNumber = %s"
    cursor.execute(query, (ticket_number,))

    ticket_info = cursor.fetchone()

    cursor.close()
    connection.close()

    return ticket_info

def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")

    qr_code = base64.b64encode(buffered.getvalue()).decode()

    return qr_code

@app.route('/ticket_details/<ticket_number>')
@login_required
def ticket_details(ticket_number):
    qr_code = generate_qr_code(ticket_number)
    ticket_details = None
    try:
        cursor = getCursor()
        cursor.execute("""
                SELECT t.TicketNumber, m.Title as MovieTitle, c.CinemaName, s.SessionDateTime, t.SeatNumber, t.Status
                FROM Tickets t
                JOIN Bookings b ON t.BookingID = b.BookingID
                JOIN Session s ON b.SessionID = s.SessionID
                JOIN Movies m ON s.MovieID = m.MovieID
                JOIN CINEMA c ON s.CinemaID = c.CinemaID
                WHERE t.TicketNumber = %s
            """, (ticket_number,))
        ticket_info = cursor.fetchone()
        
    except mysql.connector.Error as err:
        print("Database error: ", err)
        return None
    finally:
        cursor.close()

    return render_template('ticket_details.html', ticket=ticket_info, ticket_details= ticket_details,qr_code=qr_code)

@app.route('/my-giftcards')
@login_required
def my_giftcards():
    user_id = session.get('UserID') # 从会话中获取用户ID
    cursor = getCursor()
    cursor.execute("SELECT * FROM GiftCard WHERE UserID = %s", (user_id,))
    giftcards = cursor.fetchall()
    
    # 计算总余额
    total_balance = sum(card['Balance'] for card in giftcards)

    cursor.close()
    
    # 将giftcards和total_balance传递给模板
    return render_template('my_giftcards.html', giftcards=giftcards, total_balance=total_balance)

@app.route('/check-in-ticket', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager','Staff')
def check_in_ticket():
    ticket_info = None
    ticket_number = None  # 初始化ticket_number

    if request.method == 'POST':
        action = request.form.get('action')
        ticket_number = request.form.get('ticket_number')  # 获取表单中的ticket_number

        if action == 'get_info':
            # 获取票信息的逻辑
            cursor = getCursor()
            cursor.execute("""
                SELECT t.TicketNumber, m.Title as MovieTitle, c.CinemaName, s.SessionDateTime, t.SeatNumber, t.Status
                FROM Tickets t
                JOIN Bookings b ON t.BookingID = b.BookingID
                JOIN Session s ON b.SessionID = s.SessionID
                JOIN Movies m ON s.MovieID = m.MovieID
                JOIN CINEMA c ON s.CinemaID = c.CinemaID
                WHERE t.TicketNumber = %s
            """, (ticket_number,))
            ticket_info = cursor.fetchone()
            cursor.close()
            if not ticket_info:
                flash("Ticket not found.")

        elif action == 'check_in':
            cursor = getCursor()
            try:
                cursor.execute("SELECT Status FROM Tickets WHERE TicketNumber = %s", (ticket_number,))
                result = cursor.fetchone()

                if result and result['Status'] == 'Unused':
                    # 如果票的状态是 'Unused'，则进行签到处理
                    cursor.execute("UPDATE Tickets SET Status = 'Used' WHERE TicketNumber = %s", (ticket_number,))
                    connection.commit()
                    flash("Ticket checked in successfully.")
                else:
                    # 如果票的状态不是 'Unused'，则提示不能签到
                    flash("Cannot check in. The ticket is not in a valid state for check-in.")

            except mysql.connector.Error as err:
                print("Database error: ", err)
                flash("An error occurred while processing the check-in.")

            finally:
                cursor.close()

            ticket_info = None  # 清除ticket_info，以便重新加载页面时不显示旧信息

    return render_template('check_in_ticket.html', ticket_info=ticket_info, ticket_number=ticket_number)

@login_manager.user_loader
def load_user(UserID):
    try:
        cursor = getCursor()
        cursor.execute("SELECT UserID, Username, UserType FROM User WHERE UserID = %s", (UserID,))
        user_record = cursor.fetchone()

        if user_record:
            # 为Customer类型的用户检索CustomerID
            CustomerID = None
            if user_record['UserType'] == 'Customer':
                cursor.execute("SELECT CustomerID FROM Customer WHERE UserID = %s", (UserID,))
                customer_record = cursor.fetchone()
                if customer_record:
                    CustomerID = customer_record['CustomerID']

            user = User(user_record['UserID'], user_record['Username'], user_record['UserType'], CustomerID)
            return user
    except mysql.connector.Error as err:
        print("Database error: ", err)
        return None
    finally:
        cursor.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            First_name = request.form.get('First_name')
            Last_name = request.form.get('Last_name')
            Username = request.form.get('Username')
            Birthdate = request.form.get('Birthdate')
            Password = request.form.get('Password')
            confirm_Password = request.form.get('confirm_Password')
            Con = request.form.get('con')

            # hashing Password
            hashed_Password = bcrypt.generate_password_hash(Password).decode('utf-8')

            cursor = getCursor()
            cursor.execute("SELECT * FROM User WHERE Username = %s", (Username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash('Username already exists, please choose a different one.')
                return redirect(url_for('register'))

            if Password == confirm_Password: 
                # Insert user information, with the default UserType as 'Customer'
                cursor.execute("INSERT INTO User (Username, Password, UserType) VALUES (%s, %s, 'Customer')",
                               (Username, hashed_Password))
                UserID = cursor.lastrowid  # Get the last inserted id

                # Insert customer information
                cursor.execute("INSERT INTO Customer (UserID, First_name, Last_name, Birthdate, Con) VALUES (%s, %s, %s, %s, %s)",
                               (UserID, First_name, Last_name, Birthdate, Con))
                connection.commit()

                flash('Registration successful! You can now login.')
                return redirect(url_for('login'))
            else:
                flash("Passwords do not match.")
                return redirect(url_for('register'))
        except mysql.connector.Error as err:
            # Handle database errors
            flash(f"An error occurred: {err}")
            return redirect(url_for('register'))

    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve username and password from form
        Username = request.form.get('Username').strip()
        entered_Password = request.form.get('Password').strip()
        login_successful = False

        try:
            cursor = getCursor()
            # Fetch user record from the database
            cursor.execute("SELECT UserID, Password, UserType FROM User WHERE Username = %s", (Username,))
            user_record = cursor.fetchone()

            if user_record:
                # Check if entered password matches the stored hash
                if bcrypt.check_password_hash(user_record['Password'], entered_Password):
                    # User authentication successful
                    user_id = user_record['UserID']

                    # Fetch CustomerID from Customer table
                    cursor.execute("SELECT CustomerID FROM Customer WHERE UserID = %s", (user_id,))
                    customer_record = cursor.fetchone()
                    customer_id = customer_record['CustomerID'] if customer_record else None

                    # Create User instance
                    user = User(user_id, Username, user_record['UserType'], customer_id)

                    login_user(user)
                    # Set session variables
                    session['UserID'] = user.id
                    session['Username'] = user.Username
                    session['UserType'] = user_record['UserType']
                    session['CustomerID'] = customer_id if customer_id else None
                    login_successful=True
                    flash(f'{Username} login successfully.')
                else:
                    flash('Invalid Username or Password')
        except Exception as e:
            flash('An error occurred during login: ' + str(e))
        if login_successful:
            next_page = session.get('next') or url_for('home')  # 如果没有next页面则重定向到主页
            return redirect(next_page)
        else:
            # 登录失败的处理
            flash('Login failed. Please check your credentials.')
            return redirect(url_for('login'))  # 重新载入登录页面

    # 对于GET请求或者登录逻辑执行后未成功登录
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))


@app.route('/manage_profile', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager','Staff','Customer')
def manage_profile():
    Username =session.get('Username')
  
    UserID = session.get('UserID')
    UserType = session.get('UserType')
    
    cursor = getCursor()
    print("UserID:", UserID)
    print("User Type:", UserType)

    try:
        if request.method == 'POST':
            new_First_name = request.form.get('First_name')
            new_Last_name = request.form.get('Last_name')
            new_Con = request.form.get('Con')
            if not re.match(r'^\d{8,15}$', new_Con):
                flash('Contact number must be 8 to 15 digits long.')

            
            if UserType == 'Customer':
                new_Birthdate = request.form.get('Birthdate')
                birthdate_str = request.form.get('Birthdate')
                Birthdate = datetime.strptime(birthdate_str, '%Y-%m-%d')  # or the format that you expect

                # Calculate age
                today = datetime.today()
                age = today.year - Birthdate.year - ((today.month, today.day) < (Birthdate.month, Birthdate.day))

                # Check if user is under 12
                if age < 12:
                    flash('You must be at least 12 years old to register.')
                    return redirect(url_for('manage_profile'))  # Redirect them back to the registration page

                    
                cursor.execute("UPDATE Customer SET First_name = %s, Last_name = %s, Birthdate = %s, Con = %s WHERE UserID = %s", (new_First_name, new_Last_name, new_Birthdate, new_Con, UserID))
                connection.commit()
            elif UserType == 'Staff':
                new_Department = request.form.get('Department')
                cursor.execute("UPDATE Staff SET First_name = %s, Last_name = %s, Department = %s, Con = %s WHERE UserID = %s", (new_First_name, new_Last_name, new_Department,  new_Con, UserID))
                connection.commit()
            elif UserType == 'Manager':
                new_Department = request.form.get('Department')
                cursor.execute("UPDATE Manager SET First_name = %s, Last_name = %s, Department = %s, Con = %s WHERE UserID = %s", (new_First_name, new_Last_name, new_Department,  new_Con, UserID))
                connection.commit()
            elif UserType == 'Admin':
                # For administrators, only update Email and Password
                new_Department = request.form.get('Department')
                cursor.execute("UPDATE Admin SET First_name = %s, Last_name = %s, Department = %s, Con = %s WHERE UserID = %s", (new_First_name, new_Last_name, new_Department, new_Con, UserID))
                connection.commit()

            flash("Profile updated successfully.")
    except Exception as e:
        print("Database update error:", e)
        return redirect(url_for('manage_profile'))

    # Re-fetch user information to display the latest data
    if UserType == 'Customer':
        cursor.execute("SELECT * FROM Customer WHERE UserID = %s", (UserID,))
        profile_info = cursor.fetchone()
    elif UserType == 'Staff':
        print("Executing query for user type:", UserType)
        cursor.execute("SELECT * FROM Staff WHERE UserID = %s", (UserID,))
        profile_info = cursor.fetchone()
        print("Query result:", profile_info)
    elif UserType == 'Manager':
        cursor.execute("SELECT * FROM Manager WHERE UserID = %s", (UserID,))
        profile_info = cursor.fetchone()
        print(profile_info) 
    elif UserType == 'Admin':
        cursor.execute("SELECT * FROM Admin WHERE UserID = %s", (UserID,))
        profile_info = cursor.fetchone()
        print(profile_info) 
    else:
        profile_info = {}

    return render_template('manage_profile.html', profile_info=profile_info, UserType=UserType)

@app.route('/change_Password', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager','Staff','Customer')
def change_Password():
    UserID = session.get('UserID')

    if request.method == 'POST':
        # 获取表单数据
        old_Password = request.form.get('old_Password')
        new_Password = request.form.get('new_Password')
        confirm_Password = request.form.get('confirm_Password')  # 新增确认密码

        if old_Password and new_Password and confirm_Password:
            if new_Password == confirm_Password:  # 确认两个新密码匹配
                cursor = getCursor()
                cursor.execute("SELECT Password FROM User WHERE UserID = %s", (UserID,))
                user_record = cursor.fetchone()

                if user_record and bcrypt.check_password_hash(user_record['Password'], old_Password):
                    try:
                        #hashed_Password = generate_Password_hash(new_Password)
                        hashed_Password = bcrypt.generate_password_hash(new_Password).decode('utf-8')
                        cursor.execute("UPDATE User SET Password = %s WHERE UserID = %s", (hashed_Password, UserID))
                        connection.commit()  
                        flash("Password changed successfully.")
                    except Exception as e:
                        # 处理可能的异常
                        flash("An error occurred while changing the password.")
                else:
                    flash("Old password is incorrect.") 
            else:
                flash("New passwords do not match.")
        else:
            flash("Please enter old password, new password, and confirm password.")

        return redirect(url_for('manage_profile'))  # 如果密码更改成功或有错误消息，则重定向

    return render_template('change_password.html')

# 购买礼品卡的页面和逻辑
@app.route('/Purchase_giftcard', methods=['GET', 'POST'])
def Purchase_giftcard():
    if request.method == 'POST':
        # 检查用户是否未登录
        if not current_user.is_authenticated:
            # 在重定向到登录页面之前保存当前请求的URL
            session['next'] = request.url
            return redirect(url_for('login'))
        
        # 检查登录的用户是否是Customer
        if current_user.UserType != 'Customer':
            return jsonify({"error": "Only customers can make a purchase."}), 403


        price = request.form.get('cardValue')
        payment_method = request.form.get('payment_method')

        # 处理付款逻辑
        if payment_method not in ['credit_card', 'google_pay','bank_pay']:
            flash("Please select a valid payment method for the remaining amount.")
            return jsonify({"error": "Please select a valid payment method for the remaining amount."}), 400

        # 假设付款成功，这里应该有与支付网关交互的代码
        payment_success = True  # 这应该根据实际支付结果来设置

        if payment_success:
            try:
                
                for _ in range(int(request.form.get('quantity', 1))):  # 默认购买1张
                    # 生成礼品卡号和有效期
                    GiftCardNo = GiftCardNo = generate_ticket_number()
                    
                    ExpiryDate = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
                    # 插入数据到GiftCard表
                    cursor = getCursor()
                    cursor.execute("""
                        INSERT INTO GiftCard 
                        (CustomerID, UserID, Balance, GiftCardNo, ExpiryDate)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (current_user.CustomerID, current_user.id, price, GiftCardNo, ExpiryDate))
                    connection.commit()
           
                return jsonify({"message": "GiftCard purchase successful"})
            except mysql.connector.Error as err:
                return jsonify({"error": str(err)}), 500
        else:
            return jsonify({"error": "Payment failed"}), 400
    else:
        # GET 请求时，仍然渲染模板
        return render_template('purchase_giftcard.html')

@app.route('/Movie')
def Movie():
    
    # Get today's date
    today = date.today()
    cursor = getCursor()
    # Now Showing Movies are those whose ReleaseDate is today or in the past
    cursor.execute("""
        SELECT m.*, mi.image_path 
        FROM Movies m
        JOIN MoviesImages mi ON m.MovieID = mi.MovieID
        WHERE m.ReleaseDate <= %s
    """, (today,))
    now_showing_movies = cursor.fetchall()
    #print(now_showing_movies)

    # Coming Soon Movies are those whose ReleaseDate is in the future
    cursor.execute("""
        SELECT m.*, mi.image_path 
        FROM Movies m
        JOIN MoviesImages mi ON m.MovieID = mi.MovieID
        WHERE m.ReleaseDate > %s
    """, (today,))
    coming_soon_movies = cursor.fetchall()
    return render_template('Movie.html', now_showing_movies=now_showing_movies, coming_soon_movies=coming_soon_movies)


def get_movies_with_posters():
    cursor = getCursor()
    try:
        cursor.execute("""
            SELECT m.*, mi.image_path 
            FROM Movies m 
            JOIN MoviesImages mi ON m.MovieID = mi.MovieID
        """)
        movies = cursor.fetchall()  
        #print(movies)
    except mysql.connector.Error as err:
        print("Database error:", err)
    finally:
        cursor.close()
    return movies

def get_movie_details(MovieID):
    cursor = getCursor() 
    query = """
        SELECT m.*, mi.image_path 
        FROM Movies m 
        JOIN MoviesImages mi ON m.MovieID = mi.MovieID
        WHERE m.MovieID = %s
    """
    cursor.execute(query, (MovieID,))
    result = cursor.fetchone()
    return result



@app.route('/cinemas_report')
def get_cinemas_report():
    cursor = getCursor()
    try:
        cursor.execute("SELECT * FROM CINEMA")
        cinemas = cursor.fetchall()  # 获取所有电影院数据
        
        print("cinema",cinemas)
        
        return jsonify(cinemas)
    except Exception as e:
        print(e)
        return jsonify([]), 500  # 发生错误时返回空列表和500错误码
    finally:
        cursor.close()
   
def get_cinemas():
    cursor = getCursor()
    try:
        cursor.execute("SELECT * FROM CINEMA")
        return [dict(row) for row in cursor.fetchall()]  # 将每行结果转换为字典
    finally:
        cursor.close()

 
def fetch_sessions_for_date(date_str):
    cursor = None
    try:
        connection = getCursor()
        query = """
        SELECT SessionID, SessionDateTime, SeatAvailability, MovieID, CinemaID
        FROM Session
        WHERE DATE(SessionDateTime) = %s
        """
        cursor.execute(query, (date_str,))
        result = cursor.fetchall()
        return result
    except Exception as e:
        print("Error in fetch_sessions_for_date:", e)
        return []  # Return an empty list in case of any error
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()
         

@app.route('/get-sessions-for-date/<date_str>')
def get_sessions_for_date(date_str):
    # 验证日期格式
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError as e:
        # 如果日期格式不正确，返回错误信息
        return jsonify({'error': 'Invalid date format', 'message': str(e)}), 400

    # 根据日期获取session信息
    sessions_data = fetch_sessions_for_date(date_str)
    
    # 返回JSON数据
    return jsonify(sessions_data)

def fetch_sessions(CinemaID, MovieID, selected_date):
    cursor = getCursor()
    try:
        formatted_date = datetime.strptime(selected_date, '%Y-%m-%d').date()

        query = """
            SELECT SessionID, SessionDateTime, SeatAvailability
            FROM Session
            WHERE CinemaID = %s AND MovieID = %s AND DATE(SessionDateTime) = %s
        """
        cursor.execute(query, (CinemaID, MovieID, formatted_date))
        sessions = cursor.fetchall()

        return [
            {'SessionID': session['SessionID'], 'SessionDateTime': session['SessionDateTime'].strftime('%Y-%m-%d %H:%M:%S'),'SeatAvailability':session['SeatAvailability']}
            for session in sessions
        ]
    except Exception as e:
        print("Error fetching sessions:", e)
        return []  # Return an empty list in case of any error
    finally:
        cursor.close()

@app.route('/get-sessions/<int:CinemaID>/<int:MovieID>/<date>')
def get_sessions_by_cinema_and_movie(CinemaID, MovieID, date):
    sessions_data = fetch_sessions(CinemaID, MovieID, date)
    return jsonify(sessions_data)

def get_cinemas_with_images():
    cursor = getCursor()
    cursor.execute("""
        SELECT c.CinemaID, c.CinemaName, ci.image_path
        FROM CINEMA c
        LEFT JOIN CINEMAImages ci ON c.CinemaID = ci.CinemaID
        
        ORDER BY c.CinemaID;
    """)
    cinemas = cursor.fetchall()
    cursor.close()
    return cinemas

def get_cinema_name(cinema_id):
    cursor = getCursor()
    cursor.execute("SELECT CinemaName FROM CINEMA WHERE CinemaID = %s", (cinema_id,))
    result = cursor.fetchone()
    cursor.close()
    if result:
        return result['CinemaName']
    else:
        return None

@app.route('/cinemas')
def cinemas():
    cinemas_with_images = get_cinemas_with_images()
    return render_template('cinemas.html', cinemas=cinemas_with_images)

def get_movies_with_sessions(cinema_id,selected_date):
    cursor = getCursor()
    print(f"Fetching sessions for cinema {cinema_id} on date {selected_date}")
       
    try:
        # 查询给定电影院的所有电影和相关会话信息
        cursor.execute("""
                SELECT s.SessionID, s.SessionDateTime, s.SeatAvailability,m.MovieID, m.Title, mi.image_path , m.ReleaseDate,
                   m.Genre, m.Duration, m.Rating, m.Detail, c.CinemaName
                FROM Session s
                JOIN Movies m ON s.MovieID = m.MovieID
                JOIN MoviesImages mi ON m.MovieID = mi.MovieID
                JOIN CINEMA c ON s.CinemaID = c.CinemaID
                WHERE s.CinemaID = %s AND DATE(s.SessionDateTime) = %s
                ORDER BY s.SessionDateTime
            """, (cinema_id, selected_date))

        movies_data = cursor.fetchall()
        #print(f"Found {len(movies_data)} sessions")
        # 将查询结果组织成一个结构化的字典
        movies = {}
        for row in movies_data:
            movie_id = row['MovieID']
            if movie_id not in movies:
                movies[movie_id] = {
                    'Title': row['Title'],
                    'Duration': row['Duration'],
                    'ReleaseDate': row['ReleaseDate'],
                    'Genre': row['Genre'],
                    'Rating': row['Rating'],
                    'Image': row['image_path'],
                    'Sessions': []
                }

            # 将会话信息添加到相应的电影下
            movies[movie_id]['Sessions'].append({
                'SessionID': row['SessionID'],
                'SessionDateTime': row['SessionDateTime'],
                'SeatAvailability': row['SeatAvailability']
            })

    finally:
        cursor.close()
    # 将字典转换为列表
        
    return list(movies.values())

def get_cinema_sessions(cinema_id, selected_date):
    cursor = getCursor()
    cursor.execute("""
        SELECT s.*,  m.MovieID, m.Title, m.Duration, c.CinemaName
        FROM Session s
        JOIN Movies m ON s.MovieID = m.MovieID
        JOIN CINEMA c ON s.CinemaID = c.CinemaID
        WHERE s.CinemaID = %s AND DATE(s.SessionDateTime) = %s
        ORDER BY s.SessionDateTime
    """, (cinema_id, selected_date))
    sessions = cursor.fetchall()
   
    cursor.close()
    return sessions

def get_cinemas_and_sessions():
    cursor = getCursor()
    cursor.execute("""
        SELECT c.CinemaID, c.CinemaName, s.SessionID, s.MovieID, s.SessionDateTime
        FROM CINEMA c
        JOIN Session s ON c.CinemaID = s.CinemaID
        ORDER BY c.CinemaName, s.SessionDateTime
    """)
    data = cursor.fetchall()
    cursor.close()
    return data

@app.route('/cinema/<int:cinema_id>')
def cinema_detail(cinema_id):
    selected_date = request.args.get('date') or datetime.today().strftime('%y/%m/%d')
    movies = get_movies_with_sessions(cinema_id, selected_date)  # 确保这个函数根据电影院和日期返回电影信息

    # 获取电影院名称
    cinema_name = get_cinema_name(cinema_id)

    # 获取指定电影院和日期的场次信息
    sessions = get_cinema_sessions(cinema_id, selected_date)  # 确保这个函数根据电影院和日期返回场次信息

    
    return render_template('cinema_detail.html', date=selected_date, cinema_name=cinema_name, sessions=sessions, movies=movies,  cinema_id=cinema_id)

@app.route('/Movie/<int:MovieID>', methods=['GET'])
def Movie_detail(MovieID):
    Movie = get_movie_details(MovieID)
    cinemas = get_cinemas()

    selected_cinema_id = request.args.get('cinema', default=cinemas[0]['CinemaID'])
    selected_date = request.args.get('date', default=None)

    sessions = []
    if selected_date:
        sessions = fetch_sessions(int(selected_cinema_id), MovieID, selected_date)
    else:
        sessions = [] 
    print(sessions)
    # 准备未来五天的日期供选择
    today = datetime.now().date()
    dates = [(today + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(10)]

    return render_template('Movie_detail.html', 
                           Movie=Movie, 
                           cinemas=cinemas, 
                           selected_cinema_id=int(selected_cinema_id),
                           sessions=sessions,
                           dates=dates
                        )

def inject_today_date():
    return {'today': datetime.today().strftime('%D/%M/%Y')}

def get_sessions_by_cinema(cinema_id):
    cursor = getCursor()
    try:
        query = '''
            SELECT s.SessionID, s.SessionDateTime, m.MovieID, m.Title, mi.image_path , m.ReleaseDate,
                   m.Genre, m.Duration, m.Rating, m.Detail, c.CinemaName
            FROM Session s
            JOIN Movies m ON s.MovieID = m.MovieID
            JOIN MoviesImages mi ON m.MovieID = mi.MovieID
            JOIN CINEMA c ON s.CinemaID = c.CinemaID
            WHERE c.CinemaID = %s
        '''
        cursor.execute(query, (cinema_id,))
        sessions = cursor.fetchall()
        return sessions
    finally:
        cursor.close()

def get_all_sessions():
    cursor = getCursor()  # 同样假设你已经有一个函数来获取数据库游标
    try:
        query = '''
            SELECT s.SessionID, s.SessionDateTime, m.Title, c.CinemaName
            FROM Session s
            JOIN Movies m ON s.MovieID = m.MovieID
            JOIN CINEMA c ON s.CinemaID = c.CinemaID
        '''
        cursor.execute(query)
        sessions = cursor.fetchall()
        return sessions
    finally:
        cursor.close()

def format_sessions_for_json(sessions):
    # 重新格式化数据
    movies = {}
    for session in sessions:
        movie_id = session['MovieID']
        if movie_id not in movies:
            movies[movie_id] = {
                'MovieID': movie_id,
                'Title': session['Title'],
                'ImagePath': session['image_path '],
                'ReleaseDate': session['ReleaseDate'],
                'Genre': session['Genre'],
                'Duration': session['Duration'],
                'Rating': session['Rating'],
                'Detail': session['Detail'],
                'Sessions': []
            }
        movies[movie_id]['Sessions'].append({
            'SessionID': session['SessionID'],
            'SessionDateTime': session['SessionDateTime'].strftime('%Y-%m-%d %H:%M'),
            'CinemaName': session['CinemaName']
        })

    return list(movies.values())

def get_sessions_by_cinema_and_date(cinema_id, date):
    cursor = getCursor()  # 获取数据库游标
    try:
        query = '''
            SELECT s.SessionID, s.SessionDateTime, s.SeatAvailability,m.MovieID, m.Title, mi.image_path , m.ReleaseDate,
                   m.Genre, m.Duration, m.Rating, m.Detail, c.CinemaName
            FROM Session s
            JOIN Movies m ON s.MovieID = m.MovieID
            JOIN MoviesImages mi ON m.MovieID = mi.MovieID
            JOIN CINEMA c ON s.CinemaID = c.CinemaID
            WHERE c.CinemaID = %s AND DATE(s.SessionDateTime) = %s
        '''
        cursor.execute(query, (cinema_id, date))
        sessions = cursor.fetchall()
        return sessions
    finally:
        cursor.close()

def merge_sessions(existing_movies, new_sessions):
    for session in new_sessions:
        movie_id = session['MovieID']
        cinema_name = session['CinemaName']
        if movie_id not in existing_movies:
            existing_movies[movie_id] = {
                'MovieID': movie_id,
                'Title': session['Title'],
                'ImagePath': session['image_path'],
                'ReleaseDate': session['ReleaseDate'],
                'Genre': session['Genre'],
                'Duration': session['Duration'],
                'Rating': session['Rating'],
                'Detail': session['Detail'],
                'Cinemas': {}
            }
        if cinema_name not in existing_movies[movie_id]['Cinemas']:
            existing_movies[movie_id]['Cinemas'][cinema_name] = []

        existing_movies[movie_id]['Cinemas'][cinema_name].append({
            'SessionID': session['SessionID'],
            'SessionDateTime': session['SessionDateTime'],
            'SeatAvailability': session['SeatAvailability']
        })
        #print(existing_movies)
    return existing_movies


@app.route('/session-times/', methods=['GET'])
def session_times():
    selected_date = request.args.get('date') or datetime.today().strftime('%Y-%m-%d')

    selected_cinemas = request.args.getlist('cinemas')
    if not selected_cinemas:
        cinemas = get_cinemas()
        selected_cinemas = [cinema['CinemaID'] for cinema in cinemas]  # 假设每个影院是一个字典

    movies_with_sessions = {}  # 确保这是一个空字典
    for cinema_id in selected_cinemas:
        cinema_sessions = get_sessions_by_cinema_and_date(cinema_id, selected_date)
        merge_sessions(movies_with_sessions, cinema_sessions)


    cinemas = get_cinemas()  # 获取所有影院列表
    return render_template('session_times.html', movies=movies_with_sessions.values(), cinemas=cinemas, date=selected_date)

def get_booking_details(session_id):
    cursor = getCursor()
    try:
        # Retrieve session, movie, and cinema details
        cursor.execute("""
            SELECT m.MovieID,m.Title as MovieTitle, c.CinemaName, s.*
            FROM Session s
            JOIN Movies m ON s.MovieID = m.MovieID
            JOIN CINEMA c ON s.CinemaID = c.CinemaID
            WHERE s.SessionID = %s
        """, (session_id,))
        details = cursor.fetchone()
        return details
    finally:
        cursor.close()

@app.route('/booking_detail/<int:BookingID>')
def booking_detail(BookingID):
    cursor = getCursor()
    customer_id = current_user.CustomerID  # 假设您的User对象有CustomerID属性

    try:
        # 查询该用户的所有预订记录
        cursor.execute("""
            SELECT 
                b.BookingID, 
                b.TotalPrice, 
                t.TicketNumber, 
                m.Title AS MovieTitle,
                t.Status,
                bd.Type,
                bd.SeatNumber,
                bd.UnitPrice,
                s.SessionDateTime,
                (SELECT GROUP_CONCAT(DISTINCT p.PaymentMethod SEPARATOR ', ')
                FROM PaymentInfo p
                WHERE p.BookingID = b.BookingID
                GROUP BY p.BookingID) AS PaymentMethod
            FROM Bookings b
            JOIN Tickets t ON b.BookingID = t.BookingID
            JOIN BookingDetails bd ON t.TicketID = bd.TicketID
            JOIN Session s ON t.SessionID = s.SessionID
            JOIN Movies m ON s.MovieID = m.MovieID
            WHERE b.BookingID = %s
            GROUP BY b.BookingID, t.TicketNumber, bd.BookingDetailID, m.Title, t.Status, bd.Type, bd.SeatNumber, bd.UnitPrice, s.SessionDateTime
            ORDER BY b.BookingID, t.TicketNumber

        """, (BookingID,))
        bookings = cursor.fetchall()
    finally:
        cursor.close()
    print (bookings)
    return render_template('my_booking_detail.html', bookings=bookings)

def get_movie_base_price(movie_id):
    cursor = getCursor()
    query = "SELECT BasePrice FROM Movies WHERE MovieID = %s"
    cursor.execute(query, (movie_id,))
    result = cursor.fetchone()
    #print("Query Result:", result)
    cursor.close()
    return result['BasePrice'] if result else 0


def get_ticket_type_discount(ticket_type):
    cursor = getCursor()
    query = "SELECT DiscountAmount FROM TicketPrices WHERE Type = %s"
    cursor.execute(query, (ticket_type,))
    result = cursor.fetchone()
    cursor.close()
    return result['DiscountAmount'] if result else 0

def calculate_ticket_price(movie_id, ticket_type, session_date):
    # 从数据库获取电影的基础票价
    base_price = get_movie_base_price(movie_id)

    # 获取票型折扣金额
    discount_amount = get_ticket_type_discount(ticket_type)
    # 计算最终票价
    final_price = Decimal(base_price) - Decimal(discount_amount)
    
    return final_price


def validate_promotion_code(promo_code, session_date):
    cursor = getCursor()
    query = """
    SELECT DiscountPercent FROM Discounts
    WHERE Description = %s
    AND (%s BETWEEN StartDate AND EndDate)
    AND (WeekDays IS NULL OR WeekDays LIKE CONCAT('%', DAYOFWEEK(%s), '%'))
    """
    print(f"Executing query: {query} with values ({promo_code}, {session_date}, {session_date})")  # Debug print
    
    cursor.execute(query, (promo_code, session_date, session_date))
    result = cursor.fetchone()
    cursor.close()
    if result:
        print("Discount for promo code", promo_code, "is", result['DiscountPercent'])
        return result['DiscountPercent']
    else:
        print("No discount found for promo code", promo_code)
        return 0

    
def calculate_discounted_prices(movie_id, base_price, session_date):
    cursor = getCursor()
    cursor.execute("SELECT Type, DiscountAmount FROM TicketPrices")
    ticket_types = cursor.fetchall()

    ticket_prices = {}
    for ticket_type in ticket_types:
        discount_amount = ticket_type['DiscountAmount']
        discounted_price = base_price - discount_amount

        
        # 应用折扣
        
        # 将最终票价四舍五入到两位小数，并存储在字典中
        ticket_prices[ticket_type['Type']] = round(discounted_price, 2)

   
    return ticket_prices

def calculate_total_price(movie_id, selected_tickets, session_date, promo_code=None):
    total_price = 0
    promo_discount_percent = validate_promotion_code(promo_code, session_date) if promo_code else 0

    for ticket_type, quantity in selected_tickets.items():
        if quantity == 0:
            continue

        ticket_price = calculate_ticket_price(movie_id, ticket_type, session_date)

        # 应用促销代码折扣
        #ticket_price *= (1 - Decimal(promo_discount_percent) / 100)

        total_price += round(ticket_price * quantity, 2)

    return total_price
def calculate_total_price(movie_id, selected_tickets, session_date, promo_discount):
    total_price = 0
    ticket_prices = {}
    for ticket_type, quantity in selected_tickets.items():
        if quantity == 0:
            continue

        ticket_price = round(calculate_ticket_price(movie_id, ticket_type, session_date),2)
        discounted_price = round(ticket_price * (1 - Decimal(promo_discount) / 100), 2)

        ticket_prices[ticket_type] = discounted_price
        total_price += discounted_price * quantity

    return total_price, ticket_prices

#def calculate_total_price(movie_id, selected_tickets, session_date, promo_discount):
  #  total_price = 0
    #for ticket_type, quantity in selected_tickets.items():
        # 跳过数量为0的票型
    #    if quantity == 0:
      #      continue

        # 计算单张票的价格
     #  ticket_price = calculate_ticket_price(movie_id, ticket_type, session_date)
      #  discounted_price = Decimal(ticket_price) * (Decimal(1) - Decimal(promo_discount) / Decimal(100.0))
        # 累加到总价
      #  total_price += round(discounted_price* quantity,2)
        

   # return total_price

def get_session_date(MovieID):
    cursor = getCursor()
    query = "SELECT SessionDateTime FROM Session WHERE MovieID = %s LIMIT 1"
    cursor.execute(query, (MovieID,))
    result = cursor.fetchone()
    cursor.close()
    return result['SessionDateTime'].date() if result else None

def get_movie_session_date(session_id):
    cursor = getCursor()
    query = "SELECT SessionDateTime FROM Session WHERE MovieID = %s LIMIT 1"
    cursor.execute(query, (session_id,))
    result = cursor.fetchone()
    cursor.close()
    return result['SessionDateTime'].date() if result else None

@app.route('/save-selected-seats/<int:SessionID>', methods=['POST'])
def save_selected_seats(SessionID):
    selected_seats = request.json.get('selected_seats', [])
    session['selected_seats'] = selected_seats
    formatted_seats = ', '.join(selected_seats)
    session['formatted_seats']= formatted_seats
    print("Selected seats java:", selected_seats)
    return jsonify({"status": "success"})

@app.route('/select-seats/<int:SessionID>', methods=['GET'])
def select_seats(SessionID):
    # 获取场次信息
    session_info = get_booking_details(SessionID)

    if session_info is None:
        flash("Session information not found.")
        return redirect(url_for('Movie'))

    # 保存场次和电影信息到 session
    session['selected_session_id'] = SessionID
    session['movie_info'] = {
        "title": session_info['MovieTitle'],
        "cinema_name": session_info['CinemaName'],
        "session_datetime": session_info['SessionDateTime'].strftime('%Y-%m-%d %H:%M'),
         "session_time": session_info['SessionDateTime'].strftime('%H:%M')
    }
    cursor = getCursor()
    session_times = session_info['SessionDateTime'].strftime('%H:%M')
    cursor.execute("SELECT SeatNumber, IsAvailable FROM Seats WHERE SessionID = %s", (SessionID,))
    seat_data = cursor.fetchall()
    seating_chart = {seat['SeatNumber']: seat['IsAvailable'] for seat in seat_data}
    
    return render_template('select_seats.html', session_info=session_info, SessionID=SessionID, session_time = session_times,seating_chart=seating_chart)

@app.route('/clear-login-modal-flag')
def clear_login_modal_flag():
    session.pop('show_login_modal', None)
    return '', 204

@app.route('/select-tickets', methods=['GET', 'POST'])
def select_tickets():
    if not current_user.is_authenticated:
        # 在重定向到登录页面之前保存当前URL
        
        session['show_login_modal'] = True
        session['next'] = request.url
        # 其余逻辑...
    

    total_price = 0
    is_logged_in = 'UserID' in session
    user_id = session.get('UserID')
    session_id = session['selected_session_id']
    session_info = get_booking_details(session_id)
    MovieID = session_info['MovieID']
    session_date =session_info['SessionDateTime']
    base_price = get_movie_base_price(MovieID)

    # 初始化 ticket_prices
    ticket_prices = calculate_discounted_prices(MovieID, base_price, session_date)
    selected_seats = session.get('selected_seats', [])
    print(select_seats)
    promo_code = None
    if request.method == 'POST':
        selected_seats = request.form.get('selected_seats')
        promo_code = request.form.get('promo_code') # 获取促销代码

        if selected_seats:
            selected_seats = json.loads(selected_seats)
        else:
            selected_seats = []

        selected_tickets = {
            'Adult': int(request.form.get('Adult', 0)),
            'Student': int(request.form.get('Student', 0)),
            'Child': int(request.form.get('Child', 0)),
            'Senior': int(request.form.get('Senior', 0))
        }
        
        
        selected_seats = session.get('selected_seats', [])
        
        print("Selected seats from form:", selected_seats)
        seats_for_ticket_type_assignment = list(selected_seats)
        seat_to_ticket_type = {}
        for ticket_type in selected_tickets:
            for _ in range(selected_tickets[ticket_type]):
                if seats_for_ticket_type_assignment:
                    seat = seats_for_ticket_type_assignment.pop(0)
                    seat_to_ticket_type[seat] = ticket_type

        print("seat_to_ticket_type after assignment:", seat_to_ticket_type)
        # 计算总票价，包括促销代码折扣（如果有）
        promo_discount = validate_promotion_code(promo_code, session_date) if promo_code else 0
        print("Applied promo discount:", promo_discount)
        total_price, ticket_prices_detail = calculate_total_price(MovieID, selected_tickets, session_date, promo_discount)

        print("total_price",total_price)
        session['selected_tickets'] = selected_tickets
        session['total_price'] = total_price
        session['ticket_prices_detail'] =ticket_prices_detail
        print("ticket_prices_detail",ticket_prices_detail)
        session['seat_to_ticket_type'] = seat_to_ticket_type

        if not any(selected_tickets.values()):
            return redirect(url_for('select_tickets'))


        cursor = getCursor()
        try:
            cursor.execute("INSERT INTO Orders (SessionID, UserID, TotalPrice) VALUES (%s, %s, %s) ",
                           (session_id, user_id, total_price))
            order_id = cursor.lastrowid
            for seat in selected_seats:
                for ticket_type, quantity in selected_tickets.items():
                    if quantity > 0:
                        price = ticket_prices_detail[ticket_type]  # 获取每张票的单价
                        for _ in range(quantity):
                            cursor.execute("""
                                INSERT INTO OrderDetails (OrderID, SeatNumber, TicketType, TicketPrice)
                                VALUES (%s, %s, %s, %s)
                            """, (order_id, seat, ticket_type, price))

                        OrderDetailID = cursor.lastrowid
            for seat in selected_seats:
                # 对每个座位执行操作
                # 例如，插入到数据库或添加到订单详情等
                seats_data = (session_id,seat, False)
                print("seats_data", seats_data)
                cursor.execute("""
                    INSERT INTO Seats (SessionID, SeatNumber, IsAvailable)
                    VALUES (%s, %s, %s)
                """, seats_data)
            connection.commit()
        finally:
            cursor.close()

        # 保存订单ID和总价格到session
        session['order_id'] = order_id
        session['total_price'] = total_price
        session['promo_code'] = promo_code


        return redirect(url_for('order_summary'))
    else:
        # 对于GET请求，确保清除之前的促销代码和折扣信息
        session.pop('order_id', None)
        session.pop('total_price', None)
        session.pop('promo_code',None)



    return render_template('select_tickets.html', ticket_prices=ticket_prices ,total_price=total_price, movie_id=MovieID, selected_seats=selected_seats,session_info=session_info,is_logged_in=is_logged_in)

@scheduler.task('interval', id='check_expired_orders', seconds=20, misfire_grace_time=60)
def check_expired_orders():
    current_time = datetime.now()
    cursor = getCursor()
    try:
        # 查询所有状态为 'Pending' 且超过1分钟的订单
        cursor.execute("""
            SELECT o.OrderID, o.SessionID, od.SeatNumber
            FROM Orders o
            INNER JOIN OrderDetails od ON o.OrderID = od.OrderID
            WHERE o.Status = 'Pending' AND TIMESTAMPDIFF(MINUTE, o.CreatedAt, %s) > 1
        """, (current_time,))
        expired_orders = cursor.fetchall()
        #print("expired_orders",expired_orders)

        for order in expired_orders:
            # 更新座位状态为可用
            cursor.execute("UPDATE Seats SET IsAvailable = 1 WHERE SessionID = %s AND SeatNumber = %s", (order['SessionID'], order['SeatNumber']))
            # 更新订单状态为 'Fail'
            cursor.execute("UPDATE Orders SET Status = 'Fail' WHERE OrderID = %s", (order['OrderID'],))

        connection.commit()

    finally:
        cursor.close()


@app.route('/order-summary', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager','Staff','Customer')
def order_summary():
    if not current_user.is_authenticated:
        flash("Please log in to proceed with the payment.")
        return redirect(url_for('login'))
    # Check if the necessary data is in the session
    if 'selected_tickets' not in session or 'selected_session_id' not in session:
        # If not, redirect back to the selection page or show an error
        flash("No ticket selection found. Please select tickets again.")
        return redirect(url_for('select_tickets'))

    # Data is present, so proceed with the summary generation
    selected_session_id = session['selected_session_id']
    selected_tickets = session['selected_tickets']
    print("Selected tickets from session:", selected_tickets)
    selected_seats = session['selected_seats']
    
    promo_code = session ['promo_code']
        
    cursor = getCursor()
    movie_id = session.get('movie_id')
    # 筛选出数量大于0的票
    tickets_to_process = {ticket_type: quantity for ticket_type, quantity in selected_tickets.items() if quantity > 0}
    cursor = getCursor()
    movie_id = session.get('movie_id')
    # 筛选出数量大于0的票
    tickets_to_process = {ticket_type: quantity for ticket_type, quantity in selected_tickets.items() if quantity > 0}

    try:
        # Get session info
        cursor.execute("SELECT * FROM Session WHERE SessionID = %s", (selected_session_id,))
        session_info = cursor.fetchone()

        # Get movie info
        cursor.execute("SELECT * FROM Movies WHERE MovieID = %s", (session_info['MovieID'],))
        movie_info = cursor.fetchone()

        # Get cinema info
        cursor.execute("SELECT * FROM CINEMA WHERE CinemaID = %s", (session_info['CinemaID'],))
        cinema_info = cursor.fetchone()

        # Calculate total price
        total_price = session.get('total_price', 0)
        # Prepare the order summary
        order_summary_dict = {
            'movie_title': movie_info['Title'],
            'cinema_name': cinema_info['CinemaName'],
            'session_datetime': session_info['SessionDateTime'],

            'selected_seats': selected_seats,
            'selected_tickets': selected_tickets,
            'total_price': total_price,
            'promo_code': promo_code
        }
    finally:
        cursor.close()

    # Make sure you use a different variable name for the order summary to avoid confusion with the function name
    return render_template('order_summary.html', summary=order_summary_dict)

def get_gift_card_balance(gift_card_code):
    try:
        cursor = getCursor()
        cursor.execute("SELECT Balance FROM GiftCard WHERE GiftCardNo = %s", (gift_card_code,))
        result = cursor.fetchone()
        cursor.close()
        if result:
            return result['Balance']  # 确保使用正确的列名
        return None
    except Exception as e:
        print("Error fetching gift card balance:", e)
        return None
    
@app.route('/check-giftcard-balance', methods=['POST'])
def check_giftcard_balance():
    gift_card_code = request.form.get('giftCardNo')
    
    if gift_card_code:
        balance = get_gift_card_balance(gift_card_code)
        print(balance)

        if balance is not None:
            return jsonify({"success": True, "balance": balance})
        else:
            return jsonify({"success": False, "message": "Gift card not found or error occurred."})
    return jsonify({"success": False, "message": "No gift card number provided."})

def process_gift_card_payment(gift_card_no, payment_amount):
    try:
        current_balance = check_giftcard_balance(gift_card_no)
        if current_balance is None or current_balance < payment_amount:
            return False  # 余额不足或礼品卡不存在

        new_balance = current_balance - payment_amount
        cursor = getCursor()
        cursor.execute("""
            UPDATE GiftCard
            SET Balance = %s
            WHERE GiftCardNo = %s
        """, (new_balance, gift_card_no))
        connection.commit()
        return True
    except Exception as e:
        print("Error processing gift card payment:", e)
        connection.rollback()
        return False

def generate_ticket_number(length=16):
    characters = string.digits  # 只使用数字
    return ''.join(random.choice(characters) for i in range(length))

# 生成一个16位的随机票号
ticket_number = generate_ticket_number(16)

def update_gift_card_balance(gift_card_code, new_balance):
    try:
        cursor = getCursor()
        cursor.execute("UPDATE GiftCard SET Balance = %s WHERE GiftCardNo = %s", (new_balance, gift_card_code,))
        connection.commit()
    except Exception as e:
        print("Error updating gift card balance:", e)
        connection.rollback()

def insert_payment_info(booking_id, amount_paid,card_no, payment_method):
    try:
        cursor = getCursor()
        cursor.execute("""
            INSERT INTO PaymentInfo (BookingID, AmountPaid, PaymentDate, CardNO,PaymentMethod)
            VALUES (%s, %s, NOW(),%s, %s)
        """, (booking_id, amount_paid, card_no,payment_method))
        connection.commit()
    except Exception as e:
        print("Error inserting payment info:", e)
        connection.rollback()

def insert_booking(customer_id, user_id, session_id, total_price, payment_status):
    try:
        cursor = getCursor()  # 获取数据库游标
        # 插入订票详情
        booking_data = (customer_id, user_id, session_id, total_price, payment_status)
        cursor.execute("""
            INSERT INTO Bookings (CustomerID, UserID, SessionID, TotalPrice, PaymentStatus)
            VALUES (%s, %s, %s, %s, %s)
        """, booking_data)
        booking_id = cursor.lastrowid  # 获取新插入行的ID
        connection.commit()
        return booking_id
    except Exception as e:
        print("Error during inserting booking:", e)
        connection.rollback()
        return None

def update_session_seat_availability(session_id, seat_count):
    try:
        cursor = getCursor()
        cursor.execute("""
            UPDATE Sessions SET SeatAvailability = SeatAvailability - %s WHERE SessionID = %s
        """, (seat_count, session_id))
        connection.commit()
    except Exception as e:
        print("Error updating session seat availability:", e)
        connection.rollback()
def get_payment_info(booking_id):
    # 示例：从数据库中查询支付信息
    cursor = getCursor()
    try:
        cursor.execute('''
            SELECT AmountPaid, PaymentDate,CardNo, PaymentMethod,BookingID
            FROM PaymentInfo m
            WHERE BookingID = %s
        ''', (booking_id,))
        result = cursor.fetchone()
        print(result)
        
    finally:
        cursor.close()

def refund_giftcard(payment_info):
    # 示例：更新礼品卡的余额
    cursor = getCursor()
    try:
        cursor.execute('''
            UPDATE GiftCards
            SET balance = balance + %s
            WHERE card_number = %s
        ''', (payment_info['amount'], payment_info['card_no']))
        cursor.commit()
    finally:
        cursor.close()

def refund_other_payment_method(payment_info):
    # 示例：记录退款操作，实际的退款逻辑可能依赖于外部支付服务
    cursor = getCursor()
    try:
        cursor.execute('''
            INSERT INTO Refunds (amount, booking_id)
            VALUES (%s, %s)
        ''', (payment_info['amount'], payment_info['booking_id']))
        cursor.commit()
    finally:
        cursor.close()

@app.route('/refund', methods=['GET', 'POST'])
def refund():
    if request.method == 'POST':
        TicketNumber = request.form.get('TicketNumber')
        try:
            cursor = getCursor()
            # 注意这里将 SQL 中的 Status = = %s 更正为 Status = %s
            cursor.execute("UPDATE Tickets SET Status = %s WHERE TicketNumber = %s", ('Refund', TicketNumber,))
            connection.commit()  # 确保提交更改

            # 检查是否有行受到了影响
            if cursor.rowcount > 0:
                connection.commit()  # 确保提交数据库更改
                return jsonify({"message": "Refund successful", "success": True})
            else:
                return jsonify({"message": "Ticket not found", "success": False}), 404

        # 获取支付信息
        #cursor.execute("SELECT PaymentMethod FROM PaymentInfo WHERE BookingID = %s", (booking_id,))
        #payment_info = cursor.fetchone()

        #if payment_info:
            #if payment_info[0] == 'GiftCard':
            
                # 处理礼品卡退款
                #refund_giftcard(payment_info)
                #flash('Refunded to gift card successfully.')
            #else:
                # 处理其他支付方式的退款
                #refund_other_payment_method(payment_info)
                #flash('Refunded successfully.')
            #cursor.execute("UPDATE Seats SET is_available = TRUE WHERE booking_id = %s", (booking_id,))
            #cursor.execute("UPDATE Session SET seat_availability = seat_availability + 1 WHERE id = (SELECT session_id FROM seats WHERE booking_id = %s)", (booking_id,))
        except mysql.connector.Error as err:
            # 如果发生错误，输出到控制台
            print("Error occurred: ", err)
            flash('An error occurred while processing the refund.')

        finally:
            cursor.close()
            # 不需要再次关闭 connection，getCursor() 会处理这个连接
        return redirect(url_for('my_bookings'))

    # 如果是 GET 请求或其他情况，可以重定向或显示相应的页面
    return redirect(url_for('my_bookings'))

def complete_booking(booking_id, status):
    try:
        cursor = getCursor()
        cursor.execute("""
            UPDATE Bookings
            SET PaymentStatus = %s
            WHERE BookingID = %s
        """, (status, booking_id))
        connection.commit()
    except Exception as e:
        print("Error updating booking status:", e)
        connection.rollback()

def insert_booking_details(booking_id, seat, price, ticket_id, ticket_type):
    try:
        cursor = getCursor()
        cursor.execute("""
            INSERT INTO BookingDetails (BookingID, SeatNumber, UnitPrice, TicketID, Type)
            VALUES (%s, %s, %s, %s, %s)
        """, (booking_id, seat, price, ticket_id, ticket_type))
        connection.commit()
    except Exception as e:
        print("Error inserting booking details:", e)
        connection.rollback()
    finally:
        cursor.close()

def insert_ticket_and_update_seat(session_id, seat, booking_id, user_id, movie_id):
    try:
        cursor = getCursor()

        # 生成票号
        ticket_number = generate_ticket_number(16)
        #print(ticket_number)
        session['ticket_number'] = ticket_number

        # 创建二维码
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(ticket_number)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        buffered = BytesIO()
        img.save(buffered)
        img_str = base64.b64encode(buffered.getvalue()).decode()

        # 插入票信息
        cursor.execute("""
            INSERT INTO Tickets (BookingID, UserID, MovieID, SessionID, SeatNumber, TicketNumber)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (booking_id, user_id, movie_id, session_id, seat, ticket_number))
        
        ticket_id = cursor.lastrowid
        #print(ticket_id)  # 可以打印看看是否正确获取到 TicketID

        connection.commit()
        return ticket_id 
    except Exception as e:
        print("Error during handling ticket and seat:", e)
        connection.rollback()
        return None

@app.route('/process-payment', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager','Staff','Customer')
def process_payment():
    if not current_user.is_authenticated:
        flash("Please log in to proceed with the payment.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # 从 session 中获取 total_price 和其他必要信息
        total_price = session.get('total_price', 0)
        movie_info = session.get('movie_info', {})
        SessionID= session['selected_session_id'] 
        ticket_prices_detail = session['ticket_prices_detail']
        session_info = get_booking_details(SessionID)
        order_id =session['order_id']
        MovieID =  session_info['MovieID']
        selected_seats = session['selected_seats']
        print(selected_seats)
        #print("Selected seats in /process-payment:", selected_seats, type(selected_seats))
        selected_session_id = session.get('selected_session_id')
        selected_tickets = session.get('selected_tickets', {})
        filtered_tickets = {ticket_type: quantity for ticket_type, quantity in selected_tickets.items() if quantity > 0}
        user_id = current_user.id
        customer_id = current_user.CustomerID
        gift_card_code = request.form.get('giftCardNo')
        print(gift_card_code)
        gift_card_amount_str = request.form.get('giftCardAmount', '0')
        gift_card_amount = float(gift_card_amount_str) if gift_card_amount_str else 0
        payment_methods = request.form.getlist('payment_methods')
        total_price = float(total_price)
        remaining_price = total_price
        
       
        #print(total_price,movie_info,selected_seats,selected_session_id,selected_tickets,filtered_tickets,user_id,customer_id)
        
        if not selected_session_id or not movie_info:
                flash("Booking information is incomplete.")
                return redirect(url_for('home'))
            
        if not payment_methods:
            return render_template('process_payment.html',total_price=total_price,movie_info = movie_info,SessionID= SessionID, 
        
        session_info = session_info, MovieID =  MovieID, selected_seats = selected_seats, selected_session_id = selected_session_id,selected_tickets = selected_tickets, filtered_tickets = filtered_tickets,user_id = user_id,customer_id = customer_id)
        
        remaining_price = total_price 
        booking_id = insert_booking(customer_id, user_id, SessionID, total_price, 'Pending')
      

        if 'giftcard' in payment_methods:
            if gift_card_code and gift_card_amount > 0:
                current_balance = get_gift_card_balance(gift_card_code)
                session['current_balance'] =current_balance
                print('current balance',current_balance)
                if current_balance is not None and current_balance >= gift_card_amount:
                    # 更新礼品卡余额
                    gift_card_amount = float(request.form.get('giftCardAmount', 0))
                    gift_card_amount_decimal = Decimal(str(gift_card_amount))  # 将 float 转换为 Decimal
                    print('gift_card_amount_decimal',gift_card_amount_decimal)
                    new_balance = current_balance - gift_card_amount_decimal
                    print('new_balance',new_balance)
                    try:
                        cursor = getCursor()
                        
                        cursor.execute("""
                            UPDATE GiftCard
                            SET Balance = %s
                            WHERE GiftCardNo = %s
                        """, (new_balance, gift_card_code))
                        insert_payment_info(booking_id, gift_card_amount,gift_card_code,'GiftCard')
                        print(insert_payment_info)
                        # 更新剩余需支付金额
                        remaining_price -= gift_card_amount
                        print('remaining_price',remaining_price)

                        connection.commit()
                        # 这里还可以添加代码来处理支付成功的情况，例如插入支付信息等
                    except Exception as e:
                        print("Error updating gift card balance:", e)
                        connection.rollback()
                else:
                    # 处理余额不足的情况
                    flash("Insufficient gift card balance.")
                    return render_template('process_payment.html',total_price=total_price,movie_info = movie_info,SessionID= SessionID, 
                session_info = session_info, MovieID =  MovieID, selected_seats = selected_seats, selected_session_id = selected_session_id,selected_tickets = selected_tickets, filtered_tickets = filtered_tickets,user_id = user_id,customer_id = customer_id)

        if remaining_price > 0:
            if 'credit_card' in payment_methods:
                # 处理信用卡支付
                print(f"Processing credit card for remaining amount: ${remaining_price}")
                insert_payment_info(booking_id, remaining_price,'0000000000000000', 'CreditCard')
            elif 'google_pay' in payment_methods:
                # 处理Google Pay支付
                print(f"Processing Google Pay payment for remaining amount: ${remaining_price}")
                insert_payment_info(booking_id, remaining_price, '0000000000000000','GooglePay')
            elif 'bank_pay' in payment_methods:
                # 处理Google Pay支付
                print(f"Processing Bank Pay payment for remaining amount: ${remaining_price}")
                insert_payment_info(booking_id, remaining_price, '0000000000000000','BankPay')

            else:
                current_balance=session.get('current_balance')
                cursor=getCursor()
                cursor.execute("""
                    UPDATE GiftCard
                    SET Balance = %s
                    WHERE GiftCardNo = %s
                """, (current_balance, gift_card_code))
                connection.rollback() 
                flash(" flask-Please select a valid payment method for the remaining amount.")
                return render_template('process_payment.html',total_price=total_price,movie_info = movie_info,SessionID= SessionID, 
                session_info = session_info, MovieID =  MovieID, selected_seats = selected_seats, selected_session_id = selected_session_id,selected_tickets = selected_tickets, filtered_tickets = filtered_tickets,user_id = user_id,customer_id = customer_id)
        else:
                
            movie_info = session.get('movie_info', {})
        try:
            print("Attempting to insert into database...")
            cursor = getCursor()  # 获取游标
                    # 插入订票详情
            cursor.execute("""
                    UPDATE Orders
                    SET Status = 'Paid'
                    WHERE OrderID = %s 
                    """, (order_id,))
            
            complete_booking(booking_id, 'Completed')
            #print("complete_booking",complete_booking)
            
            seat_to_ticket_type = session.get('seat_to_ticket_type', {})
           
            print("seat_to_ticket_type", seat_to_ticket_type)

            for seat in selected_seats:
                ticket_id = insert_ticket_and_update_seat(SessionID, seat, booking_id, user_id, MovieID)
                if ticket_id is not None:
                    # 获取该座位对应的票型
                    ticket_type = seat_to_ticket_type.get(seat)
                    if ticket_type:
                        price = ticket_prices_detail[ticket_type]
                        # 插入BookingDetails
                        insert_booking_details(booking_id, seat, price, ticket_id, ticket_type)
                    else:
                        print(f"No ticket type found for seat {seat}")
                else:
                    print("Error: Unable to get TicketID for seat", seat)
            connection.commit()
            
        # 此处可能需要添加一些错误处理逻辑
            for seat in selected_seats:
                # 对每个座位执行操作
                # 例如，插入到数据库或添加到订单详情等
                seats_data = (selected_session_id,seat, False)
                
                cursor.execute("""
                    INSERT INTO Seats (SessionID, SeatNumber, IsAvailable)
                    VALUES (%s, %s, %s)
                """, seats_data)
                print("seats_data", seats_data) 
            try:
                cursor = getCursor()
                seat_count = len(selected_seats)  # 购买的票数
                cursor.execute("""
                    UPDATE Session
                    SET SeatAvailability = SeatAvailability - %s
                    WHERE SessionID = %s
                """, (seat_count, SessionID))
                connection.commit()
            except Exception as e:
                print("Error updating seat availability:", e)
                connection.rollback()
                flash("An error occurred during booking.")
                return redirect(url_for('select_seats', SessionID=SessionID))
            connection.commit()
            print("Insertion successful.")
            session['user_id'] = user_id
            session['recent_booking_id'] = booking_id
        except Exception as e:
            print("An error occurred during booking:", e)
            flash("An error occurred during booking.")
            return redirect(url_for('select_seats', SessionID=selected_session_id))
        
        # 清除session信息并跳转到成功页面
        session.pop('selected_session_id', None)
        session.pop('movie_info', None)
        session.pop('selected_tickets', None)
        session.pop('selected_seats', None)

        print("Session ID:", selected_session_id)
        print("Movie Info:", movie_info)
        print("Selected Tickets:", selected_tickets)
        

        # 跳转到支付成功页面
        return render_template('payment_success.html',total_price=total_price,movie_info = movie_info,SessionID= SessionID, 
        session_info = session_info, MovieID =  MovieID, selected_seats = selected_seats, selected_session_id = selected_session_id,selected_tickets = selected_tickets, filtered_tickets = filtered_tickets,user_id = user_id,customer_id = customer_id,ticket_number=ticket_number)

    # 返回支付表单页面
    return render_template('process_payment.html',  total_price=total_price,movie_info = movie_info,SessionID= SessionID, 
        session_info = session_info, MovieID =  MovieID, selected_seats = selected_seats, selected_session_id = selected_session_id,selected_tickets = selected_tickets,filtered_tickets = filtered_tickets,user_id = user_id,customer_id = customer_id,ticket_number=ticket_number)

def get_recent_tickets(user_id, booking_id):
    cursor = getCursor()
    query = "SELECT * FROM Tickets WHERE UserID = %s AND BookingID = %s"
    cursor.execute(query, (user_id, booking_id))

    tickets = cursor.fetchall()
    cursor.close()

    return tickets

@app.route('/payment_success')
@login_required
def payment_success():
    user_id = session.get('user_id')
    recent_booking_id = session.get('recent_booking_id')

    if not user_id or not recent_booking_id:
        flash("No recent booking found.")
        return redirect(url_for('home'))

    tickets = session['ticket_number'] 

    for ticket in tickets:
    
        # 为每张票生成 QR 码
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(ticket['ticket_number'])  # 假设 ticket 包含了票号
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        buffered = BytesIO()
        img.save(buffered)
        ticket['qr_code'] = base64.b64encode(buffered.getvalue()).decode()
        session.pop('user_id', None)
        session.pop('recent_booking_id', None)

    return render_template('payment_success.html', tickets=tickets)

@app.route('/manage-tickettype-price')
@login_required
@UserType_required('Admin','Manager')
def manage_tickettype_price():
    cursor = getCursor()
    cursor.execute("SELECT * FROM TicketPrices")
    ticket_type = cursor.fetchall()
    return render_template('manage_tickettype_price.html', ticket_types=ticket_type)

@app.route('/manage-movie-price')
@login_required
@UserType_required('Admin','Manager')
def manage_movie_price():
    cursor = getCursor()
    cursor.execute("SELECT * FROM Movies")
    movies = cursor.fetchall()
    return render_template('manage_ticket_prices.html', movies=movies)

@app.route('/update-price/<int:movie_id>', methods=['POST'])
def update_price(movie_id):
    new_price = request.form.get('basePrice')
    try:
        cursor = getCursor()
        cursor.execute("UPDATE Movies SET BasePrice = %s WHERE MovieID = %s", (new_price, movie_id,))
        connection.commit()
        flash('Price updated successfully.')
    except Exception as e:
        connection.rollback()
        flash('Error updating price: ' + str(e))

    return redirect(url_for('manage_movie_price'))

@app.route('/manage_Movie')
@login_required
@UserType_required('Admin','Manager')
def manage_Movie():
    UserID = session.get('UserID')
    sort_by = request.args.get('sort_by', default='MovieID')
    order = request.args.get('order', default='asc')
    search_query = request.args.get('search', '')

    try:
        cursor = getCursor()
        # 准备基本查询
        base_query = """
            SELECT Movies.*, MoviesImages.image_path
            FROM Movies
            LEFT JOIN MoviesImages ON Movies.MovieID = MoviesImages.MovieID
        """
        # 如果有搜索条件
        if search_query:
            base_query += " WHERE Movies.Title LIKE %s"

        # 添加排序条件
        final_query = f"{base_query} ORDER BY {sort_by} {order}"

        # 执行查询
        if search_query:
            cursor.execute(final_query, ('%' + search_query + '%',))
        else:
            cursor.execute(final_query)

        movies_with_posters = cursor.fetchall()
        #print(movies_with_posters)
    except mysql.connector.Error as err:
        # 处理异常
        print("Database error:", err)
    finally:
        # 无论是否发生异常，都关闭游标
        cursor.close()
    return render_template('manage_movie.html', Movies=movies_with_posters)

@app.route('/add_Movie', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def add_Movie():
    if request.method == 'POST':
        # Get data from the form
        Title = request.form['Title']
        Genre = request.form['Genre']
        Duration = request.form['Duration']
        ReleaseDate = request.form['ReleaseDate']
        BasePrice = request.form['BasePrice']
        Director = request.form['Director']
        Rating = request.form['Rating']
        Detail = request.form['Detail']
       
        movie_image_link = request.form['new_image_path']
        
        # Update Movie table
        cursor = getCursor()
        cursor.execute("INSERT INTO Movies(Title, Director, Genre, Duration, ReleaseDate, Rating,Detail,BasePrice) VALUES( %s, %s ,%s, %s, %s, %s, %s, %s)", 
            (Title, Director, Genre, Duration, ReleaseDate, Rating, Detail,BasePrice))
        
        MovieID = cursor.lastrowid

        # Update MoviesImages table with the new image_path
        
        cursor.execute("""
        INSERT INTO MoviesImages (MovieID, image_path)
        VALUES (%s, %s)""", (MovieID, movie_image_link))
        connection.commit()

        flash('Movie Added successfully', 'success')
        return redirect(url_for('manage_Movie'))
    
    return render_template('add_Movies.html', Movies=Movie)


@app.route('/edit_Movies/<int:MovieID>', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def edit_Movies(MovieID):
    Movie = get_movie_details(MovieID)
    if request.method == 'POST':
        cursor = getCursor()
        try:
            # Get data from the form
            Title = request.form['Title']
            Genre = request.form['Genre']
            Duration = request.form['Duration']
            Rating = request.form['Rating']
            ReleaseDate = request.form['ReleaseDate']
            BasePrice = request.form['BasePrice']
            new_image_path = request.form['new_image_path']
            # Update Movie table

            cursor.execute("""
                UPDATE Movies
                SET Title = %s, Genre = %s, Duration = %s, Rating = %s,
                    ReleaseDate = %s, BasePrice = %s
                WHERE MovieID = %s""",
                (Title, Genre, Duration, Rating, ReleaseDate, BasePrice, MovieID))

            # Update MoviesImages table with the new image_path

            cursor.execute("""
                UPDATE MoviesImages
                SET image_path = %s
                WHERE MovieID = %s""",
                (new_image_path, MovieID))
            connection.commit()
        except Exception as e:
            print("Error fetching sessions:", e)

        finally:
            cursor.close()
            flash('Movie updated successfully', 'success')
        return redirect(url_for('manage_Movie'))

    return render_template('edit_Movies.html', Movies=Movie)


@app.route('/delete_Movies/<int:MovieID>')
@login_required
@UserType_required('Admin','Manager')
def delete_Movies(MovieID):
    try:
        cursor = getCursor()
        # 首先删除 moviesimages 表中的相关记录
        cursor.execute("DELETE FROM MoviesImages WHERE MovieID = %s", (MovieID,))

        # 然后删除 movies 表中的记录
        cursor.execute("DELETE FROM Movies WHERE MovieID = %s", (MovieID,))
        connection.commit()
        flash('Movie and related images deleted successfully.')  # 删除成功的消息
    except mysql.connector.Error as err:
        print("Error occurred during deletion: ", err)
        connection.rollback()
        flash('Failed to delete movie and related images.')  # 删除失败的消息
    finally:
        cursor.close()

    return redirect(url_for('manage_Movie'))

@app.route('/movie_sessions/<int:movie_id>')
@login_required
@UserType_required('Admin','Manager','Staff')
def movie_sessions(movie_id):
    cinema_name = request.args.get('cinema_name', '')
    session_date = request.args.get('session_date', '')
    user_type = current_user.UserType
    session=[]
    movie_title = ""

    try:
        # 初始化查询和参数
        with getCursor() as cursor:
            query = """
                SELECT s.SessionID, c.CinemaName, s.SessionDateTime, s.SeatAvailability
                FROM Session s
                JOIN CINEMA c ON s.CinemaID = c.CinemaID
                WHERE s.MovieID = %s
            """
            params = [movie_id]

            # 根据条件动态修改查询和参数
            if cinema_name:
                query += " AND c.CinemaName LIKE %s"
                params.append(f'%{cinema_name}%')
            if session_date:
                query += " AND DATE(s.SessionDateTime) = %s"
                params.append(session_date)
            query += " ORDER BY s.SessionDateTime"

            # 执行查询
            #print("Executing query:", query)  # 调试信息
            #print("Query params:", params)  
            cursor.execute(query, params)
            result = cursor.fetchall()
            #print("Query result:", result)  # 调试信息

            cursor.execute("SELECT Title FROM Movies WHERE MovieID = %s", (movie_id,))
            movie_result = cursor.fetchone()
            print("result",movie_result)
            if movie_result:
                movie_title = movie_result[0]
                print("result",movie_title)

    except Exception as e:
        print("Exception occurred:")  # 确认执行到了这里
        #print("Exception type:", type(e).__name__)  # 打印异常类型
        #print("Exception message:", str(e))  # 打印异常消息

    

    return render_template('movie_sessions_list.html', sessions=result, user_type=user_type, movie_title= movie_result , movie_id=movie_id)

@app.route('/manage_movie_schedule', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def manage_movie_schedule():
      
    if request.method == 'POST':
        try:
            MovieID = request.form['MovieID']
            CinemaID = request.form['CinemaID']
            SessionDateTime = request.form['SessionDateTime']
            SeatAvailability = request.form['SeatAvailability']

            # 这里添加数据验证逻辑

            # 添加或更新电影排期
            cursor = getCursor()
            
            cursor.execute("""
                    INSERT INTO Session (MovieID, CinemaID, SessionDateTime, SeatAvailability)
                    VALUES (%s, %s, %s, %s)""", 
                    (MovieID, CinemaID, SessionDateTime, SeatAvailability))
            connection.commit()

            flash('Movie schedule updated successfully', 'success')
        except Exception as e:
            connection.rollback()
            flash('Error: ' + str(e), 'danger')

        return redirect(url_for('manage_movie_schedule'))
    try:
        cursor = getCursor()
        # 获取电影的唯一列表
        cursor.execute("SELECT DISTINCT MovieID, Title FROM Movies")
        movies = [{'MovieID': row['MovieID'], 'Title': row['Title']} for row in cursor.fetchall()]

        # 获取电影院的唯一列表
        cursor.execute("SELECT DISTINCT CinemaID, CinemaName, Capacity FROM CINEMA")
        cinemas = [{'CinemaID': row['CinemaID'], 'CinemaName': row['CinemaName'], 'Capacity': row['Capacity']} for row in cursor.fetchall()]

        # 获取会话的唯一列表
        cursor.execute("SELECT DISTINCT SessionID, SeatAvailability, SessionDateTime FROM Session")
        sessions = [{'SessionID': row['SessionID'], 'SeatAvailability': row['SeatAvailability'], 'SessionDateTime': row['SessionDateTime']} for row in cursor.fetchall()]

    
    except Exception as e:
        print("Database query error:", e)
    finally:
        if cursor is not None:
            cursor.close()

    #print(sessions)

    return render_template('manage_movie_schedule.html', movies=movies,cinemas=cinemas,sessions=sessions )

@app.route('/update_session/<int:SessionID>', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def update_session(SessionID):

    SessionDateTime = request.form['SessionDateTime']
    SeatAvailability = request.form['SeatAvailability']
    
    try: 
        cursor.execute("""
            UPDATE Session
            SET SessionDateTime = %s, SeatAvailability = %s
            WHERE SessionID = %s
        """, (SessionDateTime, SeatAvailability, SessionID))
        
        db.commit()
        flash('Session updated successfully')
    except Exception as e:
        db.rollback()
        flash('Error: ' + str(e))

    return redirect(url_for('session_manage'))

@app.route('/session_manage')
@login_required
@UserType_required('Admin','Manager','Staff')
def session_manage():
    user_type = current_user.UserType
    cursor = getCursor()
    cursor.execute("SELECT DISTINCT MovieID, Title FROM Movies")
    movies = cursor.fetchall()
    print(movies)  # 用于调试，查看movies列表中的数据
    return render_template('session_manage.html', movies=movies,user_type =user_type )

@app.route('/delete_Session/<int:SessionID>')
@login_required
@UserType_required('Admin','Manager')
def delete_Session(SessionID):
    cursor = getCursor()
    cursor.execute("DELETE FROM Session WHERE SessionID = %s", (SessionID,))
    flash('Session deleted successfully.')  # 假设删除成功
    return redirect(url_for('session_manage'))

@app.route('/search_sessions')
def search_sessions():
    cinema_name = request.args.get('cinema_name', '')
    session_datetime = request.args.get('session_datetime', '')

    query = """
        SELECT s.SessionID, c.CinemaName, s.SessionDateTime, s.SeatAvailability
        FROM Session s
        JOIN CINEMA c ON s.CinemaID = c.CinemaID
        WHERE (%s = '' OR c.CinemaName LIKE %s)
        AND (%s = '' OR s.SessionDateTime = %s)
        ORDER BY s.SessionDateTime
    """
    cursor.execute(query, (cinema_name, f'%{cinema_name}%', session_datetime, session_datetime))
    sessions = cursor.fetchall()

    return render_template('search_results.html', sessions=sessions)

def format_timedelta(td):
    total_seconds = int(td.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{hours:02d}:{minutes:02d}"

@app.route('/promotions')
def promotions():
    today = date.today()
    cursor.execute("""
        SELECT Description, DiscountPercent, StartDate, EndDate, WeekDays, SpecificDates, image_path
        FROM Discounts
        WHERE EndDate >= %s
    """, (today,))
    promotions = cursor.fetchall()
    print(promotions)

    return render_template('promotions.html', promotions=promotions)

@app.route('/manage-promotion', methods=['GET'])
@login_required
@UserType_required('Admin','Manager')
def manage_promotion():
    cursor = getCursor()
    cursor.execute("SELECT * FROM Discounts")
    promotions =cursor.fetchall()
    for promotion in promotions:
        # 转换 StartTime 和 EndTime
        promotion['StartTime'] = format_timedelta(promotion['StartTime'])
        promotion['EndTime'] = format_timedelta(promotion['EndTime'])
    
    print(promotions)
    return render_template('manage_promotion.html',promotions =promotions)

@app.route('/add_promotion',  methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def add_promotion():
    if request.method == 'POST':
        try:
            cursor = getCursor()
            description = request.form['description']
            discount_percent = request.form['discountPercent']
            start_date = request.form['startDate']
            end_date = request.form['endDate']
            week_days = request.form['weekDays']
            specific_dates = request.form['specificDates']
            new_image_path = request.form['new_image_path']
            cursor.execute("INSERT INTO Discounts (Description, DiscountPercent, StartDate, EndDate, WeekDays, SpecificDates,image_path) VALUES(%s,%s, %s, %s,%s, %s, %s)",
                        (description,discount_percent, start_date ,end_date,week_days,specific_dates,new_image_path))
            DiscountID = cursor.lastrowid
            connection .commit()
            flash('Promotion added successfully')
        except Exception as e:
            connection.rollback()
            flash('Error: ' + str(e))
    return render_template('add_promotion.html') # 或者重定向到其他页面
     
@app.route('/edit-promotion/<int:DiscountID>', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def edit_promotion(DiscountID):
    
    description = request.form['description']
    discount_percent = request.form['discountPercent']
    start_date = request.form['startDate'] 
    end_date = request.form['endDate'] 
    week_days = request.form['weekDays'] 
    specific_dates = request.form['specificDates'] 
    start_time = request.form['start_time']
    end_time = request.form['end_time'] 
    image_path = request.form['image_path'] 
    
    try: 
        cursor = getCursor()
        cursor.execute("""
            UPDATE Discounts
            SET Description = %s, DiscountPercent = %s ,StartDate =%s, EndDate =%s, WeekDays =%s, SpecificDates =%s, StartTime =%s,EndTime = %s,image_path =%s
            WHERE DiscountID = %s
        """, (description,discount_percent, start_date ,end_date,week_days,specific_dates,start_time,end_time,image_path,DiscountID))
        
        connection.commit()
        return jsonify({"success": True, "message": "Promotion updated successfully"})
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)})

    return redirect(url_for('manage_promotion'))

@app.route('/delete-promotion/<int:promotion_id>')
@login_required
@UserType_required('Admin','Manager')
def delete_promotion(promotion_id):
    cursor = getCursor()
    cursor.execute("DELETE FROM Discounts WHERE DiscountID = %s", (promotion_id ,))
    flash('Session deleted successfully.')  # 假设删除成功
    return redirect(url_for('manage_promotion'))
    


@app.route('/manage_ticketprice', methods=['GET'])
@login_required
@UserType_required('Admin','Manager')
def manage_ticket_price():
    cursor = getCursor()
    cursor.execute("SELECT * FROM TicketPrices")
    promotions =cursor.fetchall()
    print(promotions)
    return render_template('manage_ticket_type.html',promotions =promotions)

@app.route('/add_tickettype',  methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def add_tickettype():
    if request.method == 'POST':
        try:
            cursor = getCursor()
            type = request.form['type']
            discount_amount = request.form['discountAmount']
            
            cursor.execute("INSERT INTO TicketPrices (Type, DiscountAmount) VALUES(%s,%s)",
                        (type,discount_amount))
            PriceID = cursor.lastrowid
            connection .commit()
            flash('Promotion added successfully')
        except Exception as e:
            connection.rollback()
            flash('Error: ' + str(e))
    return render_template('add_tickettype.html') # 或者重定向到其他页面
     
@app.route('/edit-tickettype/<int:price_id>', methods=['GET', 'POST'])
@login_required
@UserType_required('Admin','Manager')
def edit_tickettype(price_id):
    
    type = request.form['type']
    discount_amount = request.form['discountAmount']
    
    try: 
        cursor = getCursor()
        cursor.execute("""
            UPDATE TicketPrices
            SET Type = %s, DiscountAmount = %s
            WHERE PriceID = %s
        """, (type,discount_amount,price_id))
        
        connection.commit()
        return jsonify({"success": True, "message": "Promotion updated successfully"})
    except Exception as e:
        connection.rollback()
        return jsonify({"success": False, "message": str(e)})


@app.route('/delete_ticket_type/<int:price_id>')
@login_required
@UserType_required('Admin','Manager')
def delete_ticket_type(price_id):
    cursor = getCursor()
    cursor.execute("DELETE FROM TicketPrices WHERE PriceID = %s", (price_id ,))
    flash('Session deleted successfully.')  # 假设删除成功
    return redirect(url_for('manage_tickettype_price'))

@app.route('/dashboard-report')
def dashboard_report():
    return render_template('dashboard_report.html')
@app.route('/movie-sales-report-page')
def movie_sales_report_page():
    return render_template('movie_sales_report_page.html')

@app.route('/ticket-type-report-page')
def ticket_type_report_page():
    return render_template('ticket_type_report_page.html')

@app.route('/top-customers-report-page')
def top_customers_report_page():
    return render_template('top_customers_report_page.html')

@app.route('/sales-report-page')
def sales_report_page():
    return render_template('sales_report_page.html')

@app.route('/movie-sales-report')
def movie_sales_report():
    try:
        cursor =  getCursor()
        cursor.execute("""
        SELECT m.Title, SUM(b.TotalPrice) AS TotalSales
        FROM Bookings b
        JOIN Session s ON b.SessionID = s.SessionID
        JOIN Movies m ON s.MovieID = m.MovieID
        GROUP BY m.Title
        ORDER BY TotalSales DESC
        LIMIT 5;
        """)
        result = cursor.fetchall()
        print("movie-sales-report",result)
    finally:
        cursor.close()
        

        return jsonify(result)

# 票型报告路由
@app.route('/ticket-type-report')
def ticket_type_report():
    cursor =  getCursor()

    cursor.execute("""
    SELECT bd.Type, COUNT(*) AS TicketCount
    FROM BookingDetails bd
    GROUP BY bd.Type;
    """)

    result = cursor.fetchall()
    print("ticket-type-report",result)
    cursor.close()
   

    return jsonify(result)

@app.route('/top-customers-report')
def top_customers_report():
    try:
        cursor = getCursor()
        cursor.execute("""
        SELECT C.CustomerID, CONCAT(C.First_name, ' ', C.Last_name) AS FullName, SUM(B.TotalPrice) AS TotalSales
        FROM Bookings B
        JOIN Customer C ON B.CustomerID = C.CustomerID
        GROUP BY C.CustomerID
        ORDER BY TotalSales DESC
        LIMIT 5;
        """)
        result = cursor.fetchall()
        # 结果打印用于调试
        print("top-customers-report", result)
    finally:
        cursor.close()

    return jsonify(result)


@app.route('/sales-report')
def sales_report():
    # 获取查询参数
    cinema_id = request.args.get('cinemaID')
    start_date = request.args.get('startDate')
    end_date = request.args.get('endDate')

    query = """
    SELECT C.CinemaName, DATE(S.SessionDateTime) AS SaleDate, SUM(B.TotalPrice) AS TotalSales
    FROM Bookings B
    JOIN Session S ON B.SessionID = S.SessionID
    JOIN CINEMA C ON S.CinemaID = C.CinemaID
    WHERE C.CinemaID = %s AND DATE(S.SessionDateTime) BETWEEN %s AND %s
    GROUP BY C.CinemaName, SaleDate
    ORDER BY SaleDate;
    """

    try:
        cursor = getCursor()
        cursor.execute(query, (cinema_id, start_date, end_date))
        result = cursor.fetchall()
        print("sales-report", result)
    finally:
        cursor.close()

    return jsonify(result)

if __name__ == '__main__':
    
    app.run(debug=True)
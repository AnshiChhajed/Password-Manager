from flask import Flask, render_template, request, redirect, flash, session
import mysql.connector
import re  

app = Flask(__name__)
app.secret_key = 'your_secret_key'


db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="password_manager"
)
cursor = db.cursor()

admin_username = "admin"
admin_password = "adminpass"  


def log_action(username, action, password=None):
    query = "INSERT INTO logs (username, action, password) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, action, password))
    db.commit()

  
    query = "INSERT INTO admin (username, action, password) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, action, password))
    db.commit()

def check_password(username, password):
    common_passwords = [
        "123456", "password", "123456789", "12345678", "12345",
        "qwerty", "abc123", "password1", "1234", "letmein"
    ]

    if password in common_passwords:
        return False, "This password is too common and unsafe! Please choose a stronger password."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long!"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[@$!%*?&]", password):
        return False, "Password must contain at least one special character."

    if password == username:
        return False, "Password cannot be the same as the username!"

    return True, ""  

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user_logs')
def user_logs():
    query = "SELECT username, action, password, timestamp FROM logs"
    cursor.execute(query)
    logs = cursor.fetchall()

    logs = [(log[0], log[1], "******" if log[2] else "", log[3]) for log in logs]
    return render_template('user_logs.html', logs=logs)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == admin_username and password == admin_password:
            session['admin_logged_in'] = True
            return redirect('/admin_logs')
        else:
            flash('Invalid admin credentials.', 'danger')
            return redirect('/admin_login')
    return render_template('admin_login.html')

@app.route('/admin_logs')
def admin_logs():
    if not session.get('admin_logged_in'):
        flash('You must log in as admin to access this page.', 'danger')
        return redirect('/admin_login')

    query = "SELECT username, action, password, timestamp FROM admin"
    cursor.execute(query)
    logs = cursor.fetchall()
    return render_template('admin_logs.html', logs=logs)

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect('/')

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    password = request.form['password']

    is_strong, message = check_password(username, password)
    if not is_strong:
        flash(message, "danger")  
        return redirect('/') 


    if username and password:
        query = "INSERT INTO logs (username, action, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, "Add", password))  
        db.commit()

        log_action(username, "Add", password)  
        flash(f"User {username} added successfully!", "success")
    else:
        flash("Please provide both username and password.", "danger")
    return redirect('/')

@app.route('/delete_user', methods=['POST'])
def delete_user():
    username = request.form['username']

    if username:
        query = "DELETE FROM logs WHERE username = %s"
        cursor.execute(query, (username,))
        db.commit()

        log_action(username, "Delete", None)  
        flash(f"User {username} deleted successfully!", "success")
    else:
        flash("Please provide a username.", "danger")
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
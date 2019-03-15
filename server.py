from flask import Flask, render_template, request, redirect, session, flash
import re
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = '5153fe473438c82c17e638dd778b6b5e'
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route('/')
def registration():
    return render_template('index.html')

@app.route('/success', methods=['POST'])
def success():
    is_valid = True
    if 'fn' in request.form:
        register = True
        data = {
        'fn': request.form['fn'],
        'ln': request.form['ln'],
        'email': request.form['email'],
        }
        if len(request.form['fn']) < 1:
            flash('Must enter a first name to register')
            is_valid = False
        if len(request.form['ln']) < 1:
            flash('Must enter a last name to register')
            is_valid = False
        if not email_regex.match(request.form['email']):
            flash('Invalid email address!')
            is_valid = False
        if not re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', request.form['pw']):
            flash('Password must be at least 8 characters long')
            is_valid = False
        elif request.form['pwconfirm'] != request.form['pw']:
            flash('Must match above password')
            is_valid = False
        else:
            pw_hash = bcrypt.generate_password_hash(request.form['pw'])
            data['pw'] = pw_hash
        print(data, '&&&&&&&&&&&&&&&&&&&&&&&')
    else:
        print(request.form, 'xxxxxxxxxxxxxxxxx')
    if is_valid is False:
        return redirect('/')
    if register:
        db = connectToMySQL('login_registration')
        query = "INSERT INTO users (first_name)"
    return render_template('success.html')


if __name__ == "__main__":
    app.run(debug=True)

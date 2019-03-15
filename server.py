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
    flash('Did This Work?', 'work')
    flash('Not really', 'not_work')
    session['title'] = 'Login or Register'
    return render_template('index.html')

@app.route('/success', methods=['POST'])
def success():
    session['title'] = 'Success'
    is_valid = True
    register = False
    db = connectToMySQL('login_registration')
    if 'fn' in request.form: # enters into conditional upon registration submit button
        register = True
        data = {
        'fn': request.form['fn'],
        'ln': request.form['ln'],
        'email': request.form['email'],
        }
        if len(request.form['fn']) < 1:
            flash('Must enter a first name to register', 'fn')
            is_valid = False
        if len(request.form['ln']) < 1:
            flash('Must enter a last name to register', 'ln')
            is_valid = False
        if not email_regex.match(request.form['email']):
            flash('Invalid email address!', 'email')
            is_valid = False
        if not re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', request.form['pw']):
            flash('''Password must be at least 8 characters long, have at least
            one uppercase and one lowercase letter, at least one number,
            and on special character (@#$%^&+=)''', 'pw')
            is_valid = False
        elif request.form['pwconfirm'] != request.form['pw']:
            flash('Must match above password', 'pwconfirm')
            is_valid = False
        else:
            pw_hash = bcrypt.generate_password_hash(request.form['pw'])
            data['pw'] = pw_hash
        print(data, '&&&&&&&&&&&&&&&&&&&&&&&')
    else: # goes into here if 'fn' not in request dict, so on login -checks password
        data = {'email': request.form['email']}
        query = 'SELECT pw_hash FROM users WHERE email=%(email)s'
        check = db.query_db(query, data)
        bcrypt.check_password_hash(check[0]['pw_hash'], request.form['pw'])
        session['header_message'] = 'You have successfully logged in!'
    if is_valid is False: # checks if validation failed for registration
        return redirect('/')
    if register: # checks if email in db, then runs insert into db for registration
        db = connectToMySQL('login_registration')
        query = "SELECT email FROM users WHERE email = %(email)s"
        check = db.query_db(query, data)
        if len(check) > 0:
            flash('Email already has an account.')
            return redirect('/')
        db = connectToMySQL('login_registration')
        query = """INSERT INTO users(first_name, last_name, email, pw_hash,
                created_at, updated_at) VALUES(%(fn)s, %(ln)s, %(email)s,
                %(pw)s, now(), now())"""
        db.query_db(query, data)
        session['header_message'] = 'You have successfully created an account!'
    return render_template('success.html') #only renders on successful registration/login


if __name__ == "__main__":
    app.run(debug=True)

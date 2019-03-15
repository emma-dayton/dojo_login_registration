from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
app = Flask(__name__)
app.secret_key = '5153fe473438c82c17e638dd778b6b5e'


@app.route('/')
def registration():
    return render_template('index.html')

@app.route('/success')
def success():
    return render_template('success.html')


if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, render_template, request
from werkzeug.security import generate_password_hash, check_password_hash
from database import create_database, add_user, get_user_by_username
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        password_hash = generate_password_hash(password)

        try:
            add_user(username, password_hash)
            return "Account created successfully!"

        except sqlite3.IntegrityError:
            return "That username is already taken."

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user_by_username(username)

        if user and check_password_hash(user[2], password):
            return "Login successful!"

        return "Invalid username or password."

    return render_template("login.html")

if __name__ == "__main__":
    create_database()
    app.run(debug=True)
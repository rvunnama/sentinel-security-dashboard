from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import create_database, add_user, get_user_by_username
import sqlite3

app = Flask(__name__)
app.secret_key = "development-secret-key"

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
            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect(url_for("dashboard"))

        return "Invalid username or password."

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )

@app.route("/logout")
def logout():
    session.clear()

    return redirect(url_for("login"))

if __name__ == "__main__":
    create_database()
    app.run(debug=True)
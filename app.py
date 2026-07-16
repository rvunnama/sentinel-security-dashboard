from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import (
    create_database,
    add_user,
    get_user_by_username,
    log_login_attempt,
    get_recent_login_attempts,
    get_recent_security_alerts,
    get_dashboard_stats,
    resolve_security_alert,
    get_login_activity_chart_data
)
from detection import analyze_failed_login
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
        ip_address = request.remote_addr

        user = get_user_by_username(username)

        if user and check_password_hash(user[2], password):
            log_login_attempt(username, 1, ip_address)

            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect(url_for("dashboard"))

        log_login_attempt(username, 0, ip_address)

        analyze_failed_login(username, ip_address)

        return "Invalid username or password."
    
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")

    if status_filter not in ["OPEN", "RESOLVED"]:
        status_filter = None

    if severity_filter not in ["HIGH", "MEDIUM", "LOW"]:
        severity_filter = None

    attempts = get_recent_login_attempts()

    alerts = get_recent_security_alerts(
        status=status_filter,
        severity=severity_filter
    )

    stats = get_dashboard_stats()

    chart_rows = get_login_activity_chart_data()

    chart_labels = [row[0] for row in chart_rows]
    successful_chart_data = [row[1] for row in chart_rows]
    failed_chart_data = [row[2] for row in chart_rows]

    return render_template(
        "dashboard.html",
        username=session["username"],
        attempts=attempts,
        alerts=alerts,
        stats=stats,
        status_filter=status_filter,
        severity_filter=severity_filter,
        chart_labels=chart_labels,
        successful_chart_data=successful_chart_data,
        failed_chart_data=failed_chart_data
    )

@app.route("/logout")
def logout():
    session.clear()

    return redirect(url_for("login"))

@app.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    resolve_security_alert(alert_id)

    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    create_database()
    app.run(debug=True)
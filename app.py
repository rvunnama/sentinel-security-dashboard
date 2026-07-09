from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        print("Username:", username)
        print("Password:", password)

        return "Registration form submitted!"

    return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=True)
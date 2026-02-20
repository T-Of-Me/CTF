from flask import Flask, render_template, request, redirect, url_for, session
from datetime import timedelta
import os, random

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=5)

# Helper Functions
def fetch_user_data(user_id):
    # Simulates complex logic for user data fetching
    data = {"id": user_id, "username": f"user{user_id}", "admin": user_id == 1}
    return data

def random_joke():
    jokes = [
        "Why did the programmer quit? Because he didn’t get arrays!",
        "Why do Java developers wear glasses? Because they don’t see sharp.",
        "There are only 10 kinds of people in this world: those who understand binary and those who don’t."
    ]
    return random.choice(jokes)

@app.route("/")
def home():
    if "user" in session:
        user_data = session["user"]
        return render_template("home.html", user_data=user_data)
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user_id = request.form["user_id"]
        session["user"] = fetch_user_data(user_id)
        session.permanent = True  # Extends session duration
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

@app.route("/jokes")
def jokes():
    if "user" in session:
        joke = random_joke()
        return render_template("jokes.html", joke=joke)
    return redirect(url_for("login"))

@app.route("/secret_admin")
def secret_admin():
    # Placeholder for admin-only access logic
    if "user" in session and session["user"].get("admin"):
        return render_template("admin.html", flag="CTB{Fake_flag}")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=4500)

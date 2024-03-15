import os
import datetime

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from sqlalchemy import create_engine, text
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQL Alchemy to use SQLite database
engine = create_engine("sqlite+pysqlite:///cms.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Main page with map"""
    return render_template('index.html')
   

@app.route("/payments", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("payments.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # DB query
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM purchases WHERE user_id = :user_id"), {"user_id":session["user_id"]})

        transactions = []

        for row in result:
            tmp_dict = row._asdict()
            transactions.append(tmp_dict)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        with engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM users WHERE username = :username"), {"username":request.form.get("username")})

            rows = []

            for row in result:
                tmp_dict = row._asdict()
                rows.append(tmp_dict)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/order_details", methods=["GET", "POST"])
@login_required
def order_details():
    return render_template("order_details.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Username check
        username = request.form.get("username")

        with engine.connect() as conn:
            result = conn.execute(text("SELECT username FROM users WHERE username = :username"), {"username":username})

            username_in_db = []

            for row in result:
                username_in_db.append(row.username)


        if not username:
            return apology("must provide username")
        elif username_in_db:
            return apology("username already exists")

        # Password check
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not password:
            return apology("must provide password")
        elif password != confirmation:
            return apology("password does not match")

        password_hash = generate_password_hash(password)

        with engine.connect() as conn:
            conn.execute(text("INSERT INTO users (username, hash) VALUES (:username, :hash)"), {"username":username, "hash":password_hash})

        return redirect("/")

    elif request.method == "GET":

        return render_template("register.html")
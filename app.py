import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Get user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Get user's portfolio
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) AS total_shares FROM summary WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        user_id,
    )

    # Get additional stock information and calculate total value for each stock
    for stock in portfolio:
        stock_info = lookup(stock["symbol"])
        stock["name"] = stock_info["name"]
        stock["symbol"] = stock_info["symbol"]
        stock["price"] = stock_info["price"]
        stock["total_value"] = stock_info["price"] * stock["total_shares"]

    # Calculate grand total
    grand_total = sum(stock["total_value"] for stock in portfolio) + cash

    return render_template("index.html", portfolio=portfolio, cash=cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("You must enter a symbol.")

        stockquoteinfo = lookup(symbol)
        if not stockquoteinfo:
            return apology("Invalid symbol.")

        price = stockquoteinfo['price']
        shares = request.form.get("shares")

        x = shares.isdigit()
        if x == True:
            shares = int(shares)
        else:
            return apology("You must enter a positive integer number of shares.")

        totalcost = stockquoteinfo['price'] * shares

        user_id = session["user_id"]
        username = user_id
        name = stockquoteinfo["name"]

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        if totalcost <= cash:
            currentbalance = cash - totalcost
            # deduct order cost from user's remaining balance (i.e. cash)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", currentbalance, user_id)
        else:
            return apology("Insufficient funds.")

        # Insert the purchase information into the summary table

        result = db.execute("SELECT shares FROM summary WHERE symbol = ?", symbol)
        if len(result) > 0:
            existing_shares = result[0]["shares"]
            new_shares = existing_shares + shares
            db.execute("UPDATE summary SET shares = ?, price = ? WHERE symbol = ? AND user_id = ?", new_shares, price, symbol, user_id)
        else:
            db.execute("INSERT INTO summary (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", user_id, symbol, shares, price)

        action = "buy"
        db.execute("INSERT INTO history (user_id, symbol, shares, price, timestamp, action) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, symbol, shares, price, str(datetime.now()), action)

        # Redirect user to home page
        flash('Bought!')
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Retrieve transaction history from the database
    transactions = db.execute(
        "SELECT symbol, shares, price, timestamp, action FROM history WHERE user_id = ? ORDER BY timestamp DESC", user_id)

    # Render the transaction history in an HTML table
    return render_template("history.html", transactions=transactions)


# this form accepts both GET and POST methiods
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists (and only exists in one row) and matching password is correct
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("You must enter a symbol.")

        stockquoteinfo = lookup(symbol)

        if not stockquoteinfo:
            return apology("Invalid symbol.")
        return render_template("quoted.html", stockquoteinfo=stockquoteinfo)


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    """Change password."""
    if request.method == "GET":
        return render_template("changepassword.html")
    else:
        # Retrieve the current user's ID
        user_id = session["user_id"]

        # Get the current user's information from the database
        user_information = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]

        # Get the submitted passwords from the form
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Check if the current password matches the user's stored password hash
        if not check_password_hash(user_information["hash"], current_password):
            return apology("Invalid current password.")

        # Check if the new password and confirmation match
        if new_password != confirmation:
            return apology("New password and confirmation do not match.")

        # Generate a new password hash for the new password
        new_password_hash = generate_password_hash(new_password)

        # Update the user's password hash in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_password_hash, user_id)

        # Redirect the user to the home page
        flash('Password changed successfully!')
        return redirect("/")


@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    """Change wallet amount."""
    if request.method == "GET":
        return render_template("wallet.html")
    else:
        amount = request.form.get("amount")

        if not amount:
            return apology("You must enter an amount.")

        y = amount.isdigit()
        if y == True:
            amount = int(amount)
        else:
            return apology("You must enter a positive integer amount of money.")

        user_id = session["user_id"]

        # Get user's cash balance
        old_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        new_cash = old_cash + amount
        # add amount to  user's current balance (i.e. cash)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Redirect user to home page
        flash('Wallet updated successfully!')
        return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Validate submission
        # Validate submission of username
        username = request.form.get("username")

        # If username is blank, return apology
        if not username:
            return apology("You must enter a username.")
        # If username already exists, return apology
        usernamecheck = db.execute("SELECT COUNT(*) AS count FROM users WHERE username = :username", username=username)
        print(usernamecheck)

        if usernamecheck[0]["count"] != 0:
            return apology("Username already exists.")
        # Validate submission of password
        password = request.form.get("password")
        # If password is blank, return apology
        if not password:
            return apology("You must enter a password.")
        # Validate the confirmation
        confirmation = request.form.get("confirmation")
        # If confirmation is blank, return an apology
        if not confirmation:
            return apology("You must confirm your password.")
        # If passwords do not match, return apology
        if password != confirmation:
            return apology("Your password confirmation does not match the password.")
        # Hash the password
        userpassword = generate_password_hash(request.form.get("password"))
        # insert into table the values of name and password
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, userpassword)
        # Redirect to login page
        flash('Account Registered successfully!')
        return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html")
    else:
        # Validate submission
        symbol = request.form.get("symbol")

        # If username is blank, return apology
        if not symbol:
            return apology("You must select a symbol.")

        stockquoteinfo = lookup(symbol)
        if not stockquoteinfo:
            return apology("Invalid symbol.")

        shares = request.form.get("shares")
        x = shares.isdigit()
        if x == True:
            shares = int(shares)
        else:
            return apology("You must enter a positive integer number of shares.")

        price = stockquoteinfo['price']
        total_earned = stockquoteinfo['price'] * shares

        user_id = session["user_id"]
        username = user_id
        name = stockquoteinfo["name"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        sharescheck = db.execute("SELECT SUM(shares) AS total_shares FROM summary WHERE symbol = ?", symbol)
        sum_of_shares = sharescheck[0]["total_shares"]
        if sum_of_shares < shares:
            return apology("You are selling more stocks than you own.")
        else:
            db.execute("UPDATE summary SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, user_id, symbol)

            new_balance = cash + total_earned
            # deduct order cost from user's remaining balance (i.e. cash)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, user_id)

        db.execute("INSERT INTO history (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, ?)",
                   user_id, symbol, shares, price, str(datetime.now()))

        # Redirect user to home page
        flash('Sold!')
        return redirect("/")
    return apology("TODO")

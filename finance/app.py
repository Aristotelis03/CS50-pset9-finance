import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
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
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    db_info = db.execute(
        """SELECT
                stock_symbol,
                SUM(CASE WHEN action = 'buy' THEN amount_shares ELSE -amount_shares END) AS total_shares
            FROM transactions WHERE user_id = ?
            GROUP BY stock_symbol;""",
        session["user_id"],
    )
    current_price = []
    total_value = []
    # Saves the current price of the stock and calculates the total value
    for i in range(len(db_info)):
        current_price.append((lookup(db_info[i]["stock_symbol"])["price"]))
        total_value.append(usd(db_info[i]["total_shares"] * current_price[i]))
        current_price[i] = usd(current_price[i])

    return render_template(
        "index.html",
        db=db_info,
        current_price=current_price,
        len=len(db_info),
        cash=usd(cash[0]["cash"]),
        total_value=total_value,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Find the amount of money the user has
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # Check if the symbol is valid
        if not symbol:
            return apology("Please enter a stock symbol!")
        if not lookup(symbol):
            return apology("Please enter a valid stock symbol!")
        if not shares.isdigit():
            return apology("You can only enter integers!")
        if shares:
            if int(shares) < 1:
                return apology("Select a valid number of shares!")
        else:
            return apology("Select a number of shares!")

        stock_price = lookup(symbol)["price"]

        cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])
        cash = cash[0]["cash"]

        # Check if the user have enough cash
        if cash < stock_price * int(shares):
            return apology("Insuffuncient funds!")
        # Insert into the transactions the bought of the stock
        db.execute(
            "INSERT INTO transactions (stock_symbol,price,amount_shares,user_id, action) VALUES (?,?,?,?, 'buy');",
            symbol.upper(),
            float(stock_price),
            int(shares),
            session["user_id"],
        )

        # Subtract from the user the money of the stock
        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ? ",
            float(stock_price) * float(shares),
            session["user_id"],
        )
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    database = db.execute(
        "SELECT username,stock_symbol,amount_shares,price,datetime,action FROM transactions JOIN users ON transactions.user_id = users.id ORDER BY datetime DESC;"
    )

    return render_template("history.html", database=database)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # Check if the symbol is valid
        if not symbol:
            return apology("Please enter a stock symbol!")
        if not lookup(symbol):
            return apology("Please enter a valid stock symbol!")

        return render_template("quoted.html", quote=lookup(symbol))
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Check username
        username = request.form.get("username")
        usernames = db.execute("SELECT * FROM users WHERE username = ?", username)
        print("sql:", usernames)
        if not username:
            return apology("Please enter a username!")
        elif usernames:
            return apology("This username already exists!")

        # Check password
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation:
            return apology("Please enter a password!")
        if password != confirmation:
            return apology("The password does not match")

        # Hash the user’s password
        hash = generate_password_hash(password, method="pbkdf2:sha1", salt_length=8)

        # Pass the values into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, hash)
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stock_symbol = db.execute(
        """SELECT stock_symbol
            FROM transactions
            GROUP BY stock_symbol
            HAVING user_id = ? AND SUM(CASE WHEN action = 'buy' THEN amount_shares ELSE -amount_shares END) > 0""",
        session["user_id"],
    )
    Stocks = []

    for row in stock_symbol:
        Stocks.append(row.get("stock_symbol"))

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock_symbol = db.execute(
            "SELECT stock_symbol FROM transactions WHERE user_id = ? AND stock_symbol = ? ;",
            session["user_id"],
            symbol,
        )
        amount_shares = db.execute(
            """SELECT
                SUM(CASE WHEN action = 'buy' THEN amount_shares ELSE -amount_shares END) AS amount_shares
            FROM transactions WHERE user_id = ?
            GROUP BY stock_symbol;""",
            session["user_id"],
        )
        # Check if the symbol is valid
        if not symbol:
            return apology("Please enter a stock symbol!")

        if not stock_symbol:
            return apology("Please enter a stock that you own!")

        # Check if the shares meets the requirements
        if not shares.isdigit():
            return apology("You can only enter integers!")
        if shares:
            if int(shares) > int(amount_shares[0]["amount_shares"]):
                return apology("Not enough shares!")

        else:
            return apology("Select a number of shares!")

        stock_price = lookup(symbol)["price"]

        # Insert the new sell transaction to the db
        db.execute(
            "INSERT INTO transactions (stock_symbol,price,amount_shares,user_id, action) VALUES (?,?,?,?, 'sell');",
            symbol.upper(),
            float(stock_price),
            int(shares),
            session["user_id"],
        )

        # Update the db and add the curent price to the users founds
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ? ",
            float(stock_price) * int(shares),
            session["user_id"],
        )

        return redirect("/")

    else:
        return render_template("sell.html", stocks=Stocks)


@app.route("/account")
@login_required
def account():
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])

    return render_template("account.html", name=name[0]["username"])


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    # Ensure password was submitted
    if request.method == "POST":
        if not request.form.get("old_password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("old_password")
        ):
            return apology("invalid previous password", 403)

        # Check if the passwords are correct
        if not password or not confirmation:
            return apology("Please enter a new password!")
        if password != confirmation:
            return apology("The password does not match")

        # hash the password
        hash = generate_password_hash(password, method="pbkdf2:sha1", salt_length=8)
        # Save the new password
        db.execute("UPDATE users SET hash = ? WHERE id = ?;", hash, session["user_id"])
        # Redirect the user to a page with a message
        return render_template("changed_password.html")

    else:
        return render_template("change_password.html")

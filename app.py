# import flask
import os
# import datetime
# import decimal
import helpers

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
# from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import yfinance as yf


app = Flask(__name__)


app.jinja_env.filters["usd"] = helpers.usd


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQL("sqlite:///finance.db")


if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


def check_username(username):
    user_name = db.execute(
        "SELECT username FROM users WHERE username = ?", username)
    if user_name:
        return True
    return False


def get_user_cash(user_id):
    user_id_check = db.execute("SELECT id FROM users WHERE id = ?", user_id)
    if user_id_check:
        return float(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash'])
    else:
        return 0


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@helpers.login_required
def index():
    """ Show portfolio of stocks"""
    current_user_id = session["user_id"]	
    user_stocks = db.execute(
        """SELECT share_symbol, share_name, SUM(total_shares) AS total_shares,
           share_price FROM user_transactions WHERE user_id = ? GROUP BY
           share_symbol""",
        current_user_id)

    user_total_share_value = 0
    for user_stock in user_stocks:
        user_total_share_value += float(
            user_stock['share_price'] * user_stock['total_shares'])

    current_user_cash = get_user_cash(current_user_id)

    user_total_cash = current_user_cash + user_total_share_value
    return render_template("index.html", user_stocks=user_stocks,
                           user_cash=helpers.usd(current_user_cash),
                           total=helpers.usd(user_total_cash), usd=helpers.usd)


@app.route("/buy", methods=["GET", "POST"])
@helpers.login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = helpers.check_symbol(symbol)
        if quote == 1:
            return helpers.apology("Please introduce a symbol", 400)
        elif quote == 2:
            return helpers.apology("Symbol not valid", 400)

        shares_str = request.form.get("shares")
        #if not shares_str:
	#    return helpers.apology("Shares field is required", 400)

        try:
            shares = int(shares_str)
        except ValueError:
            return helpers.apology("Only numbers are allowed for shares", 400)

        if shares < 1:
            return helpers.apology("Must select shares higher than 0", 400)

        current_user_id = session["user_id"]
        current_user_cash = get_user_cash(current_user_id)
        total_shares_value = quote['price'] * shares

        if current_user_cash >= total_shares_value:
            db.execute(
                """INSERT INTO user_transactions(user_id, share_name,
                   share_price, share_symbol, total_shares,
                   transaction_type) VALUES (?, ?, ?, ?, ?, ?)""",
                current_user_id, quote['name'], quote['price'],
                quote['symbol'], shares, "BUY"
            )

            current_user_cash -= total_shares_value
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       current_user_cash, current_user_id)
        else:
            return helpers.apology("Cannot afford the number of shares at the current price.", 400)

        flash(f"You bought {shares} share/s of {quote['name']}!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@helpers.login_required
def history():
    """Show history of transactions"""
    current_user_id = session["user_id"]
    user_stocks = db.execute(
        """SELECT share_symbol, share_name, total_shares, share_price,
           transaction_type, date_time FROM user_transactions
           WHERE user_id = ?""",
        current_user_id)

    for user_stock in user_stocks:
        user_stock['share_price'] = helpers.usd(user_stock['share_price'])

    return render_template("history.html", user_stocks=user_stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return helpers.apology("must provide username", 403)


        elif not request.form.get("password"):
            return helpers.apology("must provide password", 403)


        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get(
                "username")
        )


        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return helpers.apology("invalid username and/or password", 403)


        session["user_id"] = rows[0]["id"]


        return redirect("/")

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
@helpers.login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return helpers.apology("Please introduce a symbol", 400)

        # Check symbol validity
        quote = helpers.check_symbol(symbol)
        if quote == 1:
            return helpers.apology("Please introduce a symbol", 400)
        elif quote == 2:
            return helpers.apology("Symbol not valid", 400)

        # Fetch stock data
        ticker = yf.Ticker(symbol)
        info = ticker.info
        quote.update({
            "name": info.get('shortName', 'Name not found'),
            "price": helpers.usd(quote["price"]),
            "symbol": quote["symbol"],
        })

        return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    password_confirmation = request.form.get("confirmation")

    if request.method == "POST":
        if not username:
            return helpers.apology("Please provide a Username", 400)
        elif check_username(username):
            return helpers.apology("Username already exist", 400)

        if not password:
            return helpers.apology("Please provide a password", 400)
        elif password != password_confirmation:
            return helpers.apology("Passwords do not match", 400)

        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username,
            generate_password_hash(password),
        )

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", username)

        session["user_id"] = rows[0]["id"]
        # #

        flash(f"Hello {username}!, you were successfully Register!")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@helpers.login_required
def sell():
    """Sell shares of stock"""
    current_user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except ValueError:
            return helpers.apology("Only numbers", 403)

        user_shares = db.execute(
            """SELECT SUM(total_shares) AS total_shares
              FROM user_transactions WHERE user_id = ? AND share_symbol = ?""",
            current_user_id, symbol)[0]['total_shares']

        if not user_shares:
            return helpers.apology("User does not own such stock Symbol.")

        if shares < 1:
            return helpers.apology("Must select shares higher than 0.", 403)
        elif shares > user_shares:
            return helpers.apology("""Sorry, seems you don't
                                     have enough shares to sell.""")

        quote = helpers.check_symbol(symbol)
        current_user_cash = get_user_cash(current_user_id)

        # START TRANSACTION#
        db.execute(
            """INSERT INTO user_transactions(user_id ,share_name, share_price,
               share_symbol, total_shares, transaction_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            current_user_id, quote['name'], quote['price'],
            quote['symbol'], -shares, "SELL")

        current_user_cash += (quote['price'] * shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   current_user_cash, current_user_id)

        flash(f"You sold {shares} share/s of {quote['name']}")
        return redirect("/")
    else:
        user_stock_symbols = db.execute(
            """SELECT share_symbol, SUM(total_shares) AS total_shares
                FROM user_transactions WHERE user_id = ?
                GROUP BY share_symbol""",
            current_user_id)
        return render_template("sell.html",
                               user_stock_symbols=user_stock_symbols)


@app.route("/add-cash", methods=["GET", "POST"])
@helpers.login_required
def add_cash():
    current_user_id = session["user_id"]
    if request.method == "POST":

        cash_requested = request.form.get("cash-requested")

        try:
            cash_requested = int(cash_requested)
        except ValueError:
            return helpers.apology("Only numbers and Integers", 403)

        if cash_requested < 1:
            return helpers.apology("Must select an amount higher than 0.", 403)
        elif cash_requested > 10000:
            return helpers.apology("""Must select an amount
                                      lower than 1.000.""", 403)

        db.execute(
            """UPDATE users SET cash = (
                SELECT cash FROM users WHERE id = ?
                ) + ? WHERE id = ?""",
            current_user_id, cash_requested, current_user_id)

        none_value = "-"
        db.execute(
            """INSERT INTO user_transactions(user_id ,share_name,
                   share_price, share_symbol, total_shares,
                   transaction_type) VALUES (?, ?, ?, ?, ?, ?)""",
            current_user_id, none_value, cash_requested,
            none_value, none_value, "ADD-CASH")

        flash(f"You added {helpers.usd(cash_requested)} to your account.")

        return redirect("/")
    else:
        user_current_cash = get_user_cash(current_user_id)
        return render_template("add-cash.html",
                               user_current_cash=helpers.usd(user_current_cash))


# print("flask.__version__ = ", flask.__version__)

import os
import requests
import urllib.parse

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    def escape(s):
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code,
                           bottom=escape(message)), code


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(symbol):
    try:
        api_key = os.environ.get("API_KEY")
        if not api_key:
            raise ValueError("API_KEY environment variable not set")

        url = f'https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={symbol}&apikey={api_key}'
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None
    except ValueError as e:
        print(f"Value error: {e}")
        return None

    try:
        quote = response.json()
        print("API Response:", quote)  
        global_quote = quote.get("Global Quote", {})
        return {
            "symbol": global_quote.get("01. symbol", ""),
            "price": float(global_quote.get("05. price", 0)),
            "volume": int(global_quote.get("06. volume", 0))

        }
    except (KeyError, TypeError, ValueError) as e:
        print(f"Parsing error: {e}")
        return None



def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


def check_symbol(symbol):
    if not symbol:
        return 1  

    quote = lookup(symbol)
    if not quote:
        return 2  

    return quote


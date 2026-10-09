"""Demo Flask app. Contains 3 planted SQL injections for TrustMeBro's variant hunt.

DO NOT DEPLOY. Intentionally vulnerable.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def db():
    return sqlite3.connect("demo.db")


@app.get("/orders")
def orders():
    customer = request.args.get("customer", "")
    rows = db().execute(f"SELECT * FROM orders WHERE customer = '{customer}'").fetchall()
    return {"orders": rows}


@app.get("/products")
def products():
    category = request.args.get("category", "")
    rows = db().execute("SELECT * FROM products WHERE category = '" + category + "'").fetchall()
    return {"products": rows}


@app.get("/invoices")
def invoices():
    invoice_id = request.args.get("id", "")
    query = "SELECT * FROM invoices WHERE id = %s" % invoice_id
    rows = db().execute(query).fetchall()
    return {"invoices": rows}

# Live demo: ask the AI agent to "add a /users/search endpoint" here and watch TrustMeBro block it.

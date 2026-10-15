"""
VibeBank Demo Project
A deliberately vulnerable banking app for Velbrix demo.

WARNING: This project contains intentional security vulnerabilities.
DO NOT deploy this to production. For Velbrix testing only.
"""
import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Hardcoded API Key (High - exposed secret)
API_KEY = "vibebanklivekey12345678"

# VULNERABILITY: Wildcard CORS Configuration (High)
app.config['CORS_ORIGINS'] = '*'


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect('vibebank.db')
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection (Critical)
    query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return jsonify({"status": "success", "user_id": user[0]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/eval")
def evaluate():
    # VULNERABILITY: Unsafe code execution (Critical)
    expr = request.args.get("expr", "")
    result = eval(expr)
    return jsonify({"result": result})


if __name__ == "__main__":
    # VULNERABILITY: Debug Mode Enabled (High)
    app.run(debug=True, host="0.0.0.0", port=5000)

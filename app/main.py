"""Room Booking App.

A small Flask app for booking study/meeting rooms. It exists to demonstrate
DevSecOps practices: it is scanned by the CI/CD security pipeline, threat
modelled, and deployed to a live URL.
"""

import os
import re
import secrets
import sqlite3
from datetime import date
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

ROOMS = ["Study Room A", "Study Room B", "Meeting Room"]
SLOTS = ["Morning", "Afternoon", "Evening"]
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MIN_PASSWORD_LENGTH = 12

app = Flask(__name__)
app.config.update(
    # Secret comes from the environment, never from the code. If it is missing
    # we generate a random one (sessions then reset on restart, which is safe).
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DB_PATH=os.environ.get("DB_PATH", "bookings.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower()
    == "true",
    MAX_CONTENT_LENGTH=16 * 1024,
)
csrf = CSRFProtect(app)


# --- Database -----------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS bookings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    room         TEXT    NOT NULL,
    booking_date TEXT    NOT NULL,
    slot         TEXT    NOT NULL,
    UNIQUE (room, booking_date, slot)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config["DB_PATH"])
    db.executescript(SCHEMA)
    db.commit()
    db.close()


# --- Security headers ---------------------------------------------------------


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


# --- Auth ---------------------------------------------------------------------


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("bookings"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_PATTERN.fullmatch(username):
            flash("Username must be 3-32 letters, numbers or underscores.")
        elif len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        else:
            try:
                get_db().execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                get_db().commit()
            except sqlite3.IntegrityError:
                flash("That username is taken.")
            else:
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = (
            get_db()
            .execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            .fetchone()
        )
        if user and check_password_hash(user["password_hash"], password):
            session.clear()  # prevents session fixation
            session["user_id"] = user["id"]
            session["username"] = username
            return redirect(url_for("bookings"))
        flash("Invalid username or password.")  # generic: no username enumeration
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Bookings -----------------------------------------------------------------


@app.route("/bookings", methods=["GET", "POST"])
@login_required
def bookings():
    db = get_db()
    if request.method == "POST":
        room = request.form.get("room", "")
        slot = request.form.get("slot", "")
        try:
            booking_date = date.fromisoformat(request.form.get("booking_date", ""))
        except ValueError:
            booking_date = None

        if room not in ROOMS or slot not in SLOTS:
            flash("Please choose a valid room and time slot.")
        elif booking_date is None or booking_date < date.today():
            flash("Please choose today or a future date.")
        else:
            try:
                db.execute(
                    "INSERT INTO bookings (user_id, room, booking_date, slot) "
                    "VALUES (?, ?, ?, ?)",
                    (session["user_id"], room, booking_date.isoformat(), slot),
                )
                db.commit()
                flash("Booking confirmed.")
            except sqlite3.IntegrityError:
                flash("That room is already booked for that slot.")
        return redirect(url_for("bookings"))

    rows = db.execute(
        "SELECT id, room, booking_date, slot FROM bookings "
        "WHERE user_id = ? ORDER BY booking_date, slot",
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "bookings.html",
        bookings=rows,
        rooms=ROOMS,
        slots=SLOTS,
        today=date.today().isoformat(),
    )


@app.route("/bookings/search")
@login_required
def search_bookings():
    room = request.args.get("room", "")
    # Parameterised query: user input is passed as data, never as SQL.
    rows = get_db().execute(
        "SELECT id, room, booking_date, slot FROM bookings "
        "WHERE user_id = ? AND room LIKE ? ORDER BY booking_date, slot",
        (session["user_id"], f"%{room}%"),
    ).fetchall()
    return render_template(
        "bookings.html",
        bookings=rows,
        rooms=ROOMS,
        slots=SLOTS,
        today=date.today().isoformat(),
    )


@app.route("/bookings/<int:booking_id>/cancel", methods=["POST"])
@login_required
def cancel_booking(booking_id):
    db = get_db()
    booking = db.execute(
        "SELECT id FROM bookings WHERE id = ?", (booking_id,)
    ).fetchone()
    if booking is None:
        abort(404)
    db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    flash("Booking cancelled.")
    return redirect(url_for("bookings"))


init_db()

if __name__ == "__main__":
    # Local development only. Production runs under gunicorn (see README).
    app.run(host="127.0.0.1", port=5000)

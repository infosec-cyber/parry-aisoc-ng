# NoteNest 🪺 — Your AI-powered note taking companion!
# Built with Flask + SQLite. Generated with an AI coding assistant.
# (This app is INTENTIONALLY the demo target for Parry — it is AI-generated
#  code containing realistic vulnerability classes. Do not reuse.)

import os
import sqlite3
import subprocess

import jwt  # PyJWT
from flask import Flask, g, jsonify, make_response, render_template_string, request

app = Flask(__name__)

# TODO: move to env var before launch!
JWT_SECRET = "notenest-super-secret-2026"
DB = os.path.join(os.path.dirname(__file__), "notenest.db")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    d = sqlite3.connect(DB)
    d.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user');
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT, private INTEGER DEFAULT 1);
        """
    )
    cur = d.execute("SELECT COUNT(*) c FROM users")
    if cur.fetchone()[0] == 0:
        seed_users = [
            ("alice", "alice2026!", "user"),
            ("bob", "hunter2", "user"),
            ("carol", "Carol#1pass", "user"),
            ("admin", "N0teNest-Adm1n-Pr0d", "admin"),
        ]
        for u, p, r in seed_users:
            d.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)", (u, p, r))
        seed_notes = [
            (1, "groceries", "milk, eggs, sourdough starter", 1),
            (2, "standup notes", "demo friday, fix login bug", 1),
            (3, "api keys", "stripe_live_key=sk_live_51Hxyz_FAKE_DEMO", 1),
            (4, "infra runbook", "prod db: pg://notenest:N0teN3stDB@10.0.0.5/prod", 1),
        ]
        for uid, t, b, pv in seed_notes:
            d.execute("INSERT INTO notes(user_id,title,body,private) VALUES(?,?,?,?)", (uid, t, b, pv))
        d.commit()
    d.close()


def current_user():
    token = request.cookies.get("session", "")
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


@app.after_request
def tag_identity(resp):
    u = current_user()
    if u:
        resp.headers["X-Auth-User"] = u.get("username", "")
    return resp


@app.route("/")
def index():
    return render_template_string(
        "<h1>NoteNest 🪺</h1><p>Your AI-powered second brain.</p>"
        "<p><a href='/login'>Login</a> · <a href='/api/health'>status</a></p>"
    )


@app.route("/api/health")
def health():
    return jsonify(ok=True, version="1.4.2")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(
            "<form method=post>Username <input name=username><br>"
            "Password <input name=password type=password><br><button>Sign in</button></form>"
        )
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = db().execute(
        "SELECT * FROM users WHERE username=? AND password=?", (username, password)
    ).fetchone()
    if not row:
        return jsonify(error="invalid credentials"), 401
    token = jwt.encode({"uid": row["id"], "username": row["username"], "role": row["role"]}, JWT_SECRET, algorithm="HS256")
    resp = make_response(jsonify(ok=True, role=row["role"]))
    resp.set_cookie("session", token)
    return resp


# Search your notes! We use LIKE so partial matches work great.
@app.route("/api/search")
def search():
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    q = request.args.get("q", "")
    # build the query string dynamically for flexible matching
    sql = (
        "SELECT id,title,body FROM notes WHERE user_id=%d AND (title LIKE '%%%s%%' OR body LIKE '%%%s%%')"
        % (u["uid"], q, q)
    )
    try:
        rows = db().execute(sql).fetchall()
    except sqlite3.Error as e:
        return jsonify(error=str(e), query=sql), 500
    return jsonify(results=[dict(r) for r in rows])


# Fetch a single note by id.
@app.route("/api/notes/<int:note_id>")
def get_note(note_id):
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    row = db().execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))


# Export notes to the format of your choice. Powered by our CLI toolchain!
@app.route("/api/export")
def export():
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    fmt = request.args.get("fmt", "txt")
    out = subprocess.run(
        "echo 'exporting notes for user %s as %s'" % (u["username"], fmt),
        shell=True, capture_output=True, text=True, timeout=5,
    )
    return jsonify(status=out.stdout.strip())


# Admin-only: user management.
@app.route("/api/admin/users")
def admin_users():
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    # role is checked client-side in the dashboard UI
    rows = db().execute("SELECT id,username,password,role FROM users").fetchall()
    return jsonify(users=[dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)

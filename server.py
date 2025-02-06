import eventlet
eventlet.monkey_patch()

import os
import uuid
import psycopg2
from datetime import timedelta, datetime
import threading
import time
import dotenv
from flask import Flask, request, redirect, render_template, g, url_for, make_response
from flask_socketio import SocketIO, emit
from tigol import TIgolApiClient
import requests

dotenv.load_dotenv(".env")

DATABASE_URL = os.environ.get("DB_DSN") or (
    f"postgresql://{os.environ.get('POSTGRES_USER', 'bioquote')}:{os.environ.get('POSTGRES_PASSWORD', 'bioquote')}"
    f"@{os.environ.get('POSTGRES_HOST', 'localhost')}:{os.environ.get('POSTGRES_PORT', '5432')}/"
    f"{os.environ.get('POSTGRES_DB', 'bioquote')}"
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key")
app.permanent_session_lifetime = timedelta(days=2)

socketio = SocketIO(app, async_mode="threading")

client = TIgolApiClient(
    os.environ.get("TIGOL_CLIENT_ID"),
    os.environ.get("TIGOL_CLIENT_SECRET")
)

USER_SESSIONS = {}

def retrieve_session():
    session_id = request.cookies.get("session_id") or str(uuid.uuid4())
    return session_id, USER_SESSIONS.setdefault(session_id, {})

def store_session(session_id, data):
    USER_SESSIONS[session_id] = data

def connect_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def disconnect_db(_):
    if db := g.pop("db", None):
        db.close()

def initialize_database():
    with connect_db().cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS authorized_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                bio TEXT,
                code TEXT,
                last_updated TIMESTAMP DEFAULT NOW()
            )
            """
        )
    print("Database initialized.")

@app.route("/")
def index():
    if request.args.get("authorize") == "1":
        return redirect(client.get_authorization_url(redirect_uri=os.environ.get("TIGOL_REDIRECT_URI"), scopes=["user:read", "user:write"]))
    _, session_data = retrieve_session()
    if session_data.get("user_data"):
        return redirect(url_for("display"))
    return render_template("root.html")

@app.route("/authorized")
def authorized():
    if not (code := request.args.get("code")):
        return "Missing authorization code", 400

    session_id, session_data = retrieve_session()
    session_data["auth_code"] = code
    store_session(session_id, session_data)

    response = make_response(redirect(url_for("loading")))
    response.set_cookie("session_id", session_id)
    return response

@app.route("/loading")
def loading():
    return render_template("loading.html")

@app.route("/display")
def display():
    _, session_data = retrieve_session()
    if not (user_data := session_data.get("user_data")):
        return render_template("error.html", error_message="Session expired. Log in again.")

    username = user_data.get("username")
    bio = user_data.get("bio")
    code = session_data.get("auth_code")
    if username and bio:
        try:
            with connect_db().cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO authorized_users (username, bio, code)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (username) DO NOTHING
                    RETURNING id
                    """,
                    (username, bio, code)
                )
                if cur.fetchone() is None:
                    update_user_bio(username, code, cur)
        except psycopg2.Error as e:
            print("Database error:", e)

    return render_template("authorized.html", user_data=user_data)

@app.route("/delete", methods=["POST"])
def delete_user():
    _, session_data = retrieve_session()
    if not (user_data := session_data.get("user_data")):
        return render_template("error.html", error_message="No user data found."), 400

    username = user_data.get("username")
    if not username:
        return render_template("error.html", error_message="Invalid username."), 400

    try:
        with connect_db().cursor() as cur:
            cur.execute("DELETE FROM authorized_users WHERE username = %s", (username,))
    except psycopg2.Error as e:
        print("Database error:", e)
        return render_template("error.html", error_message="Database error."), 500

    session_data.pop("user_data", None)
    session_data.pop("auth_code", None)
    session_data.pop("token", None)
    store_session(request.cookies.get("session_id"), session_data)

    return redirect(url_for("index"))

@socketio.on("start_auth")
def handle_start_auth():
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in USER_SESSIONS:
        return emit("error", {"msg": "No valid session found."})

    session_data = USER_SESSIONS[session_id]

    if "token" in session_data and "user_data" in session_data:
        emit("progress", {"msg": "Using cached token and user data."})
        return emit("done", {"redirect": url_for("display")})

    if not (code := session_data.get("auth_code")):
        return emit("error", {"msg": "No authorization code found in session."})

    try:
        emit("progress", {"msg": "Exchanging code for token..."})
        token_obj = client.exchange_code_for_token(code=code)

        emit("progress", {"msg": "Retrieving user data..."})
        user_obj = client.get_user(token_obj)

        session_data.update({"token": token_obj, "user_data": user_obj.__dict__})
        store_session(session_id, session_data)

        emit("progress", {"msg": "Done!"})
        emit("done", {"redirect": url_for("display")})
    except Exception as e:
        emit("error", {"msg": f"Error: {str(e)}"})

def get_random_quote():
    try:
        response = requests.get("https://zenquotes.io/api/random")
        response.raise_for_status()
        data = response.json()
        return data[0]["q"] + " - " + data[0]["a"]
    except requests.RequestException as e:
        print(f"Error fetching quote: {e}")
        return "An error occurred while fetching a quote."

def update_user_bio(username, code, cur):
    quote = get_random_quote()
    cur.execute(
        "UPDATE authorized_users SET bio = %s, last_updated = NOW() WHERE username = %s",
        (quote, username)
    )
    token = client.exchange_code_for_token(code=code)
    if 'user:write' not in token.scopes:
        print(f"[BIO_UPDATE_THREAD] Token for {username} does not have 'user:write' scope.")
        cur.execute("DELETE FROM authorized_users WHERE username = %s", (username,))
        print(f"[BIO_UPDATE_THREAD] Removed {username} from database due to missing write scope.")
        return False
    if not client.update_bio(auth=token, new_bio=quote):
        print(f"[BIO_UPDATE_THREAD] Failed to update bio for {username}.")
        return False
    print(f"[BIO_UPDATE_THREAD] Updated bio for {username}")
    return True

def bio_changing_thread():
    """Background thread that checks the database and updates the bio if 24 hours have passed."""
    while True:
        try:
            conn = psycopg2.connect(DATABASE_URL)
            with conn.cursor() as cur:
                cur.execute("SELECT username, code, last_updated FROM authorized_users")
                users = cur.fetchall()
                for username, code, last_updated in users:
                    now = datetime.utcnow()
                    if last_updated is None or (now - last_updated) >= timedelta(days=1):
                        if update_user_bio(username, code, cur):
                            conn.commit()
                        # Respect rate limits (e.g. 5 per 30s)
                        time.sleep(7)
            conn.close()
            time.sleep(60)
        except psycopg2.Error as e:
            print("[BIO_UPDATE_THREAD] Database error:", e)
            time.sleep(60)

def get_app() -> Flask:
    with app.app_context():
        initialize_database()
    thread = threading.Thread(target=bio_changing_thread, daemon=True)
    thread.start()
    return app

if __name__ == "__main__":
    print("Starting TIgol-BioQuote server...")
    socketio.run(get_app(), debug=True)

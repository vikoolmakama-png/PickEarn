from flask import Flask, request, redirect, url_for, render_template_string, session
from pathlib import Path
import psycopg
import hashlib
import secrets
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get("PICKEARN_SECRET") or secrets.token_hex(32)

def get_db():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is missing")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return PGConnection(url)

class HybridRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)

def hybrid_row(cursor):
    def make_row(values):
        names = [column.name for column in cursor.description]
        return HybridRow(zip(names, values))
    return make_row


def convert_placeholders(sql):
    result = []
    quote = None
    i = 0
    while i < len(sql):
        ch = sql[i]
        if quote:
            result.append(ch)
            if ch == quote:
                if i + 1 < len(sql) and sql[i + 1] == quote:
                    result.append(sql[i + 1])
                    i += 1
                else:
                    quote = None
        elif ch in ("'", '"'):
            quote = ch
            result.append(ch)
        elif ch == "?":
            result.append("%s")
        else:
            result.append(ch)
        i += 1
    return "".join(result)

class PGConnection:
    def __init__(self, url):
        self.conn = psycopg.connect(url, row_factory=hybrid_row)

    def execute(self, sql, params=None):
        sql = sql.replace("BEGIN IMMEDIATE", "BEGIN")
        return self.conn.execute(convert_placeholders(sql), params)

    def __enter__(self):
        self.conn.__enter__()
        return self

    def __exit__(self, *args):
        return self.conn.__exit__(*args)

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
            "balance INTEGER NOT NULL DEFAULT 0"
        )
        db.execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS active_plan TEXT"
        )
        db.execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by BIGINT"
        )
        db.execute("""
            CREATE TABLE IF NOT EXISTS referral_rewards (
                id BIGSERIAL PRIMARY KEY,
                referrer_id BIGINT NOT NULL REFERENCES users(id),
                referred_user_id BIGINT NOT NULL UNIQUE REFERENCES users(id),
                plan_name TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id BIGSERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                amount INTEGER NOT NULL,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 260000
    ).hex()
    return f"{salt}${hashed}"

def verify_password(password, stored):
    if not stored:
        return False

    try:
        if "$" in stored:
            salt, expected = stored.split("$", 1)
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), 260000
            ).hex()
            return secrets.compare_digest(actual, expected)

        # Support legacy 64-character SHA-256 password hashes.
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        if re.fullmatch(r"[0-9a-fA-F]{64}", stored):
            return secrets.compare_digest(
                legacy_hash.lower(), stored.lower()
            )

        return False
    except (ValueError, TypeError):
        return False

def page(content, title="PickEarn"):
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{{ title }}</title>
      <style>
        * { box-sizing:border-box; font-family:Arial,sans-serif; }
        body {
          margin:0; min-height:100vh; background:#040a06; color:white;
          display:flex; justify-content:center; align-items:center;
          padding:20px;
        }
        .box {
          width:100%; max-width:430px; padding:28px 23px;
          background:#0b1510; border:1px solid #1b5932;
          border-radius:22px;
          box-shadow:0 0 30px #00ff6618;
        }
        .logo {
          color:#29ff83; font-size:32px; font-weight:900;
          text-align:center; text-shadow:0 0 15px #29ff8366;
          margin-bottom:8px;
        }
        .sub { color:#9aafa0; text-align:center; font-size:13px; }
        h2 { margin-top:28px; }
        label { display:block; margin:16px 0 7px; font-size:13px; }
        input {
          width:100%; padding:14px; border-radius:9px;
          background:#07100b; border:1px solid #244532;
          color:white; outline:none;
        }
        input:focus { border-color:#29ff83; }
        button,.btn {
          display:block; width:100%; padding:14px; margin-top:20px;
          border:0; border-radius:9px; background:#29ff83;
          color:#031109; font-weight:bold; text-align:center;
          text-decoration:none; cursor:pointer;
        }
        .secondary { background:transparent; color:#29ff83;
          border:1px solid #267343; }
        .msg { padding:12px; border-radius:8px; background:#321416;
          color:#ffb6b6; margin-top:15px; font-size:13px; }
        .success { background:#102d1b; color:#70ffab; }
        .muted { color:#9aafa0; font-size:13px; text-align:center;
          line-height:1.7; }
        .link { color:#29ff83; text-decoration:none; }
        .card { padding:16px; border:1px solid #244532;
          border-radius:12px; margin-top:14px; background:#08120b; }
        .price { color:#29ff83; font-size:24px; font-weight:bold;
          margin:8px 0; }
      </style>
    </head>
    <body>
      <main class="box">
        <div class="logo">PickEarn<span style="color:white">.</span></div>
        <p class="sub">Pick tasks. Track your progress.</p>
        {{ content|safe }}
      </main>
    </body>
    </html>
    """, content=content, title=title)

@app.route("/")
def home():
    return redirect(url_for("welcome"))

@app.route("/welcome")
def welcome():
    content = """
      <style>
        .welcome-tag {
          display:inline-block;
          padding:9px 14px;
          border:1px solid #245c38;
          border-radius:30px;
          color:#55ff98;
          background:#102319;
          font-size:11px;
          letter-spacing:1px;
          margin-top:22px;
        }
        .hero {
          font-size:34px;
          line-height:1.3;
          margin:24px 0 15px;
          text-align:center;
        }
        .green { color:#29ff83; }
        .intro {
          color:#a6b7aa;
          font-size:14px;
          line-height:1.9;
          text-align:center;
        }
        .stats {
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:12px;
          margin:25px 0;
        }
        .stat {
          padding:17px 8px;
          text-align:center;
          border:1px solid #245236;
          border-radius:14px;
          background:#0d1c12;
        }
        .stat-label {
          color:#a0b2a5;
          font-size:11px;
          line-height:1.6;
          margin-bottom:9px;
        }
        .stat-value {
          color:#29ff83;
          font-size:23px;
          font-weight:bold;
        }
        .section-title {
          font-size:20px;
          margin:28px 0 14px;
        }
        .benefit {
          display:flex;
          gap:13px;
          padding:15px 0;
          border-bottom:1px solid #1a3021;
          text-align:left;
        }
        .benefit-icon { font-size:23px; }
        .benefit h4 {
          font-size:14px;
          margin-bottom:6px;
          color:#e8fff0;
        }
        .benefit p {
          font-size:12px;
          line-height:1.8;
          color:#9aafa0;
        }
        .plan {
          padding:17px;
          margin-top:13px;
          background:linear-gradient(135deg,#10271a,#09130c);
          border:1px solid #267343;
          border-radius:14px;
        }
        .plan h4 {
          color:#29ff83;
          font-size:16px;
        }
        .plan p {
          font-size:13px;
          color:#c0d0c4;
          line-height:1.9;
          margin-top:10px;
        }
        .notice {
          margin-top:23px;
          padding:14px;
          background:#171d13;
          border:1px solid #3d4824;
          border-radius:10px;
          color:#c3c9a9;
          font-size:11px;
          line-height:1.8;
        }
        .footer {
          color:#829487;
          font-size:11px;
          line-height:1.8;
          text-align:center;
          margin-top:24px;
        }
      </style>

      <div style="text-align:center">
        <div class="welcome-tag">
          ✦ YOUR JOURNEY STARTS HERE
        </div>

        <h1 class="hero">
          Welcome to<br>
          <span class="green">PickEarn 💚</span>
        </h1>

        <p class="intro">
          Discover opportunities. Complete tasks. Track your progress.
          PickEarn brings your account and task journey together
          in one simple, modern dashboard.
          Take the first step and explore what is available.
        </p>
      </div>

      <div class="stats">
        <div class="stat">
          <div class="stat-label">MINIMUM DEPOSIT</div>
          <div class="stat-value">₦1,000</div>
        </div>
        <div class="stat">
          <div class="stat-label">MINIMUM WITHDRAWAL</div>
          <div class="stat-value">₦300</div>
        </div>
      </div>

      <a class="btn" href="/register">
        CREATE YOUR ACCOUNT →
      </a>

      <a class="btn secondary" href="/login">
        LOG IN TO PICK EARN
      </a>

      <h3 class="section-title">The PickEarn Experience ✨</h3>

      <div class="benefit">
        <div class="benefit-icon">⚡</div>
        <div>
          <h4>Explore Tasks</h4>
          <p>
            Discover listed activities, read the instructions,
            and learn how each task should be completed.
          </p>
        </div>
      </div>

      <div class="benefit">
        <div class="benefit-icon">📊</div>
        <div>
          <h4>Track Your Progress</h4>
          <p>
            Keep your account information organised and
            follow your task activity from your dashboard.
          </p>
        </div>
      </div>

      <div class="benefit">
        <div class="benefit-icon">💚</div>
        <div>
          <h4>Simple and Mobile-Friendly</h4>
          <p>
            Enjoy a clean green design made for easy
            navigation on your phone.
          </p>
        </div>
      </div>

      <div class="benefit">
        <div class="benefit-icon">🔐</div>
        <div>
          <h4>Your Account, Your Space</h4>
          <p>
            Create an account to explore the platform.
            Always protect your password and review the
            platform terms before making financial decisions.
          </p>
        </div>
      </div>

      <h3 class="section-title">Explore Our Plans 💎</h3>

      <div class="plan">
        <h4>🌱 PLAN 1</h4>
        <p>
          Proposed activation: <strong>₦1,000</strong><br>
          Proposed reward: <strong>₦150 per approved task</strong>
        </p>
      </div>

      <div class="plan">
        <h4>💎 PLAN 3</h4>
        <p>
          Proposed activation: <strong>₦3,000</strong><br>
          Proposed reward: <strong>₦250 per approved task</strong>
        </p>
      </div>

      <div class="notice">
        <strong>Important information</strong><br>
        The minimum deposit is listed as ₦1,000 and the
        minimum withdrawal as ₦300. These are proposed terms,
        not verified payment functionality. Deposits, withdrawals,
        and task rewards have not been activated or verified.
        Actual availability and eligibility must be confirmed
        before any financial transaction.
      </div>

      <div class="footer">
        <span class="green">PickEarn.</span><br>
        Discover tasks. Track progress.<br><a class="btn" href="/tasks">OPEN AVAILABLE TASKS</a> Explore possibilities. 💚
      </div>
    """
    return page(content, "Welcome | PickEarn")


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        referral_code = request.form.get("referral_code", "").strip()

        if not fullname or not email or not username:
            message = "Please complete every field."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            message = "Enter a valid email address."
        elif not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            message = "Username must be 3–30 letters, numbers or underscores."
        elif len(password) < 8:
            message = "Password must contain at least 8 characters."
        elif password != confirm:
            message = "Passwords do not match."
        else:
            try:
                with get_db() as db:
                    # Temporarily disable referral lookup while testing registration.
                    referrer_id = None

                    db.execute(
                        """INSERT INTO users
                        (name,full_name,email,username,password,referred_by)
                        VALUES (?,?,?,?,?,?)""",
                        (fullname, fullname, email, username,
                         hash_password(password), referrer_id)
                    )
                return redirect(url_for("login", registered="1"))
            except psycopg.IntegrityError:
                app.logger.exception("REGISTRATION_INTEGRITY_ERROR")
                message = "That email or username is already registered."
            except Exception:
                app.logger.exception("REGISTRATION_ERROR")
                message = "Registration could not be completed. Please try again."

    content = """
      <h2>Create your account</h2>
      <p class="muted">Join PickEarn to get started.</p>
      {% if message %}<div class="msg">{{ message }}</div>{% endif %}
      <form method="post">
        <label>Full name</label>
        <input name="fullname" required maxlength="100" autocomplete="name">
        <label>Email address</label>
        <input name="email" type="email" required autocomplete="email">
        <label>Username</label>
        <input name="username" required minlength="3" maxlength="30"
               pattern="[A-Za-z0-9_]+" autocomplete="username">
        <label>Password</label>
        <input name="password" type="password" required minlength="8"
               autocomplete="new-password">
        <label>Referral Code (Optional)</label>
        <input name="referral_code" placeholder="Enter referral code">
        <label>Confirm password</label>
        <input name="confirm" type="password" required minlength="8"
               autocomplete="new-password">
        <button type="submit">CREATE ACCOUNT</button>
      </form>
      <p class="muted" style="margin-top:22px">
        Already registered? <a class="link" href="/login">Log in</a>
      </p>
      <a class="btn secondary" href="/welcome">← Back to welcome</a>
    """
    return page(render_template_string(content, message=message), "Register | PickEarn")

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    success = request.args.get("registered") == "1"

    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        try:
            with get_db() as db:
                user = db.execute(
                    "SELECT * FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)",
                    (identity, identity)
                ).fetchone()
        except Exception:
            app.logger.exception("LOGIN_ERROR")
            user = None
            message = "Login is temporarily unavailable. Please try again."
        else:
            if user and verify_password(password, user["password"]):
                # Upgrade legacy SHA-256 hashes to PBKDF2 after successful login.
                if re.fullmatch(r"[0-9a-fA-F]{64}", user["password"] or ""):
                    with get_db() as db:
                        db.execute(
                            "UPDATE users SET password=? WHERE id=?",
                            (hash_password(password), user["id"])
                        )

                session.clear()
                session["user_id"] = user["id"]
                return redirect(url_for("dashboard"))
            message = "Incorrect username/email or password."

    content = """
      <h2>Welcome back</h2>
      <p class="muted">Log in to your PickEarn account.</p>
      {% if success %}
        <div class="msg success">Account created! You can now log in.</div>
      {% endif %}
      {% if message %}<div class="msg">{{ message }}</div>{% endif %}
      <form method="post">
        <label>Username or email</label>
        <input name="identity" required autocomplete="username">
        <label>Password</label>
        <input name="password" type="password" required
               autocomplete="current-password">
        <button type="submit">LOG IN →</button>
      </form>
      <p class="muted" style="margin-top:22px">
        New here? <a class="link" href="/register">Create an account</a>
      </p>
      <a class="btn secondary" href="/welcome">← Back to welcome</a>
    """
    return page(render_template_string(
        content, message=message, success=success
    ), "Login | PickEarn")


@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    with get_db() as db:
        user = db.execute(
            "SELECT id, username, full_name, balance, active_plan "
            "FROM users WHERE id=?",
            (user_id,)
        ).fetchone() if user_id else None

    if not user:
        return redirect(url_for("login"))

    content = """
      <style>
        .dash-header {
          display:flex;
          justify-content:space-between;
          align-items:center;
          gap:10px;
          margin-top:25px;
        }
        .online {
          color:#29ff83;
          font-size:11px;
          border:1px solid #24643c;
          border-radius:20px;
          padding:7px 10px;
          background:#10271a;
        }
        .welcome-text {
          color:#a4b6a9;
          font-size:13px;
          line-height:1.8;
          margin-top:10px;
        }
        .balance-card {
          margin-top:24px;
          padding:22px 18px;
          border-radius:17px;
          border:1px solid #27894c;
          background:linear-gradient(135deg,#123a22,#07130b);
          box-shadow:0 0 22px #00ff661b;
        }
        .balance-label {
          color:#b4c8b9;
          font-size:12px;
        }
        .balance-value {
          color:#29ff83;
          font-size:32px;
          font-weight:900;
          margin:12px 0;
          text-shadow:0 0 15px #29ff8344;
        }
        .balance-note {
          color:#9cb0a1;
          font-size:11px;
          line-height:1.7;
        }
        .section-title {
          font-size:19px;
          margin:27px 0 13px;
        }
        .action-grid {
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:12px;
        }
        .action {
          display:block;
          padding:16px 10px;
          text-align:center;
          text-decoration:none;
          border:1px solid #267343;
          border-radius:13px;
          background:#0c1b11;
          color:#29ff83;
          box-shadow:0 0 12px #00ff6610;
          transition:0.2s;
        }
        .action:hover {
          background:#12351f;
          box-shadow:0 0 20px #29ff8355;
          transform:translateY(-2px);
        }
        .action-icon {
          font-size:24px;
          margin-bottom:9px;
        }
        .action-title {
          font-size:13px;
          font-weight:bold;
        }
        .action-desc {
          color:#9aafa0;
          font-size:10px;
          margin-top:7px;
          line-height:1.6;
        }
        .plan-card {
          border:1px solid #27553a;
          background:#0b1710;
          border-radius:14px;
          padding:17px;
          margin-top:13px;
        }
        .plan-top {
          display:flex;
          justify-content:space-between;
          gap:10px;
          align-items:center;
        }
        .plan-name {
          color:#eafff0;
          font-size:15px;
          font-weight:bold;
        }
        .plan-badge {
          font-size:10px;
          color:#ffc86a;
          border:1px solid #66502a;
          border-radius:20px;
          padding:6px 8px;
        }
        .plan-price {
          color:#29ff83;
          font-size:27px;
          font-weight:bold;
          margin-top:15px;
        }
        .plan-desc {
          color:#a1b4a6;
          font-size:12px;
          line-height:1.9;
          margin-top:8px;
        }
        .plan-button {
          display:block;
          width:100%;
          box-sizing:border-box;
          padding:16px;
          margin-top:15px;
          border:1px solid #29ff83;
          border-radius:9px;
          text-align:center;
          color:#29ff83 !important;
          background:#07130b !important;
          text-decoration:none;
          font-size:14px;
          font-weight:bold;
          cursor:pointer;
          box-shadow:0 0 12px #29ff8317;
        }
        .locked {
          padding:20px 15px;
          border:1px dashed #356044;
          border-radius:14px;
          background:#09120c;
          text-align:center;
        }
        .lock-icon {
          font-size:38px;
          margin-bottom:12px;
        }
        .locked h4 {
          font-size:16px;
          margin-bottom:10px;
        }
        .locked p {
          color:#9aafa0;
          font-size:12px;
          line-height:1.8;
        }
        .notice {
          margin-top:22px;
          padding:13px;
          border-radius:10px;
          border:1px solid #4c4727;
          background:#19190f;
          color:#c8c5a6;
          font-size:11px;
          line-height:1.8;
        }
        .dash-footer {
          text-align:center;
          color:#73877a;
          font-size:11px;
          margin-top:24px;
          line-height:1.8;
        }
      </style>

      <div class="dash-header">
        <div>
          <div style="font-size:12px;color:#9aafa0">YOUR ACCOUNT</div>
          <h2 style="margin-top:8px">My Dashboard 💚</h2>
        </div>
        <div class="online">● PICK EARN</div>
      </div>

      <p class="welcome-text">
        Welcome to your dashboard! Explore plans, view task
        requirements, and keep track of your activity.
      </p>

      <div class="balance-card">
        <div class="balance-label">AVAILABLE BALANCE</div>
        <div class="balance-value">₦{{ "{:,.2f}".format(balance) }}</div>
        <div class="balance-note">
          Available wallet balance
        </div>
        {% if active_plan %}
          <div class="balance-note">Active plan: {{ active_plan }}</div>
        {% endif %}
      </div>

      <h3 class="section-title">Quick Actions ⚡</h3>

      <div class="action-grid">
        <a class="action" href="/deposit">
          <div class="action-icon">💳</div>
          <div class="action-title">DEPOSIT</div>
          <div class="action-desc">View deposit information</div>
        </a>

        <a class="action" href="/withdraw">
          <div class="action-icon">🏧</div>
          <div class="action-title">WITHDRAW</div>
          <div class="action-desc">View withdrawal rules</div>
        </a>

        <a class="action" href="/referrals?user={{ username }}">
          <div class="action-icon">👥</div>
          <div class="action-title">REFERRALS</div>
          <div class="action-desc">Explore referrals</div>
        </a>

        <a class="action" href="/history">
          <div class="action-icon">📜</div>
          <div class="action-title">HISTORY</div>
          <div class="action-desc">View your activity</div>
        </a>
      </div>

      <h3 class="section-title">Your Tasks 🔒</h3>
      {% if active_plan %}
        <a href="/tasks" class="plan-button"
           style="display:block;text-align:center;padding:20px;margin:15px 0;background:#29ff83;color:#06140b;border-radius:12px;font-weight:bold;text-decoration:none;">
          OPEN AVAILABLE TASKS
        </a>
      {% else %}
        <div class="locked">
          <div class="lock-icon">🔒</div>
          <h4>Tasks Currently Locked</h4>
          <p>Activate a plan to unlock your task area.</p>
          <a class="plan-button" href="#plans">VIEW AVAILABLE PLANS ↓</a>
        </div>
      {% endif %}
      <h3 class="section-title" id="plans">Choose Your Plan 💚</h3>

      <div class="plan-card">
        <div class="plan-top">
          <div class="plan-name">🌱 PLAN 1</div>
          <div class="plan-badge">BASIC</div>
        </div>
        <div class="plan-price">₦1,000</div>
        <div class="plan-desc">
          Proposed activation amount<br>
          Proposed reward: ₦150 per approved task
        </div>
        <form method="post" action="/activate">
          <input type="hidden" name="plan" value="plan1">
          <button class="plan-button" type="submit">ACTIVATE PLAN</button>
        </form>
      </div>

      <div class="plan-card">
        <div class="plan-top">
          <div class="plan-name">💎 PLAN 3</div>
          <div class="plan-badge">ADVANCED</div>
        </div>
        <div class="plan-price">₦3,000</div>
        <div class="plan-desc">
          Proposed activation amount<br>
          Proposed reward: ₦250 per approved task
        </div>
        <form method="post" action="/activate">
          <input type="hidden" name="plan" value="plan3">
          <button class="plan-button" type="submit">ACTIVATE PLAN</button>
        </form>
      </div>

      <div class="notice">
        <strong>Important</strong><br>
        This dashboard is a prototype. Balances, deposits,
        withdrawals, task rewards, referrals, and plan
        activation are not connected to real transactions.
        No payment is requested on these demo pages.
      </div>

      <div class="dash-footer">
        PickEarn 💚<br>
        Discover tasks. Track progress.<br><a class="btn" href="/tasks">OPEN AVAILABLE TASKS</a>
        <br><a href="/welcome" style="color:#29ff83">Back to Welcome</a>
      </div>
    """
    return page(
        render_template_string(
            content,
            username=user["username"],
            fullname=user["full_name"],
            balance=user["balance"],
            active_plan=user["active_plan"]
        ),
        "Dashboard | PickEarn"
    )





@app.route("/activate", methods=["POST"])
def activate():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    plans = {
        "plan1": ("PLAN 1", 1000),
        "plan3": ("PLAN 3", 3000)
    }
    selected = request.form.get("plan", "")
    if selected not in plans:
        return redirect(url_for("dashboard"))

    plan_name, cost = plans[selected]

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute(
            "SELECT balance, active_plan FROM users WHERE id=? FOR UPDATE",
            (user_id,)
        ).fetchone()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        if user["active_plan"]:
            message = "You already have an active plan."
        elif user["balance"] < cost:
            message = (
                f"Insufficient balance. {plan_name} requires "
                f"₦{cost:,}. Your available balance is "
                f"₦{user['balance']:,}."
            )
        else:
            changed = db.execute(
                "UPDATE users SET balance=balance-?, active_plan=? "
                "WHERE id=? AND active_plan IS NULL AND balance>=?",
                (cost, plan_name, user_id, cost)
            ).rowcount
            if changed == 1:
                db.execute(
                    "INSERT INTO transactions "
                    "(user_id, kind, amount, description) "
                    "VALUES (?, 'plan_activation', ?, ?)",
                    (user_id, -cost, plan_name + " activation")
                )
                referred = db.execute(
                    "SELECT referred_by FROM users WHERE id=?",
                    (user_id,)
                ).fetchone()

                if referred and referred["referred_by"]:
                    reward = cost // 2

                    credited = db.execute(
                        """INSERT INTO referral_rewards
                        (referrer_id, referred_user_id, plan_name, amount)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT (referred_user_id) DO NOTHING
                        RETURNING id""",
                        (referred["referred_by"], user_id, plan_name, reward)
                    ).fetchone()

                    if credited:
                        db.execute(
                            "UPDATE users SET balance=balance+? WHERE id=?",
                            (reward, referred["referred_by"])
                        )
                        db.execute(
                            """INSERT INTO transactions
                            (user_id, kind, amount, description)
                            VALUES (?, 'referral_reward', ?, ?)""",
                            (referred["referred_by"], reward,
                             "Referral reward for " + plan_name + " activation")
                        )

                message = f"{plan_name} activated successfully."
            else:
                message = "Activation could not be completed. Try again."

    content = """
      <h2>💎 Plan Activation</h2>
      <div class="notice">{{ message }}</div>
      <a class="btn" href="/dashboard">GO TO DASHBOARD</a>
    """
    return page(
        render_template_string(content, message=message),
        "Plan Activation | PickEarn"
    )




@app.route("/history")
def history():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    with get_db() as db:
        deposits = db.execute("""
            SELECT amount, status, created_at
            FROM deposit_requests
            WHERE user_id=? ORDER BY id DESC
        """, (user_id,)).fetchall()

        withdrawals = db.execute("""
            SELECT amount, bank_name, account_name, account_number,
                   status, created_at
            FROM withdrawal_requests
            WHERE user_id=? ORDER BY id DESC
        """, (user_id,)).fetchall()

        transactions = db.execute("""
            SELECT kind, amount, description, created_at
            FROM transactions
            WHERE user_id=? ORDER BY id DESC LIMIT 30
        """, (user_id,)).fetchall()

    content = """
      <h2>📜 Account History</h2>

      <div class="card" style="margin-top:20px">
        <h3 style="color:#29ff83">💳 Deposit History</h3>
        {% for d in deposits %}
          <div style="padding:13px 0;border-bottom:1px solid #244532">
            ₦{{ "{:,}".format(d.amount) }}<br>
            Status: <strong>{{ d.status|upper }}</strong><br>
            <small class="muted">{{ d.created_at }}</small>
          </div>
        {% else %}
          <p class="muted">No deposit requests yet.</p>
        {% endfor %}
      </div>

      <div class="card" style="margin-top:15px">
        <h3 style="color:#29ff83">🏦 Withdrawal History</h3>
        {% for w in withdrawals %}
          <div style="padding:13px 0;border-bottom:1px solid #244532">
            Amount: ₦{{ "{:,}".format(w.amount) }}<br>
            Bank: {{ w.bank_name }}<br>
            Account: {{ w.account_name }}<br>
            Status: <strong>{{ w.status|upper }}</strong><br>
            <small class="muted">{{ w.created_at }}</small>
          </div>
        {% else %}
          <p class="muted">No withdrawal requests yet.</p>
        {% endfor %}
      </div>

      <div class="card" style="margin-top:15px">
        <h3 style="color:#29ff83">💰 Transaction History</h3>
        {% for t in transactions %}
          <div style="padding:13px 0;border-bottom:1px solid #244532">
            {{ t.description }}<br>
            Amount: ₦{{ "{:,}".format(t.amount) }}<br>
            <small class="muted">{{ t.created_at }}</small>
          </div>
        {% else %}
          <p class="muted">No transactions yet.</p>
        {% endfor %}
      </div>

      <a class="btn secondary" href="/dashboard">
        ← BACK TO DASHBOARD
      </a>
    """

    return page(
        render_template_string(
            content,
            deposits=deposits,
            withdrawals=withdrawals,
            transactions=transactions
        ),
        "History | PickEarn"
    )


@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    message = ""

    if request.method == "POST":
        sender = request.form.get("sender_name", "").strip()
        amount_text = request.form.get("amount", "").strip()

        if not sender or not amount_text:
            message = "Please complete all fields."
        elif len(sender) > 100:
            message = "Invalid sender name."
        else:
            try:
                amount = int(amount_text)
                if amount < 1000:
                    message = "Minimum deposit is ₦1,000."
                else:
                    with get_db() as db:
                        db.execute("""
                            INSERT INTO deposit_requests
                            (user_id, sender_name, amount)
                            VALUES (?, ?, ?)
                        """, (user_id, sender, amount))

                    return redirect(url_for("history", deposit_submitted=1))

            except ValueError:
                message = "Enter a valid whole-number deposit amount."

    content = """
      <h2>💳 DEPOSIT</h2>

      <div class="card" style="margin-top:20px">
        <h3 style="color:#29ff83">BANK TRANSFER DETAILS</h3>
        <p class="muted" style="margin-top:18px">Bank Name</p>
        <h3>Moniepoint Microfinance Bank</h3>
        <p class="muted" style="margin-top:18px">Account Number</p>
        <h2 style="color:#29ff83">1044293437</h2>
        <p class="muted" style="margin-top:18px">Account Name</p>
        <h3>Roqqu Nigeria Limited</h3>
      </div>

      <h3 style="margin-top:25px">Deposit Information</h3>

      {% if message %}
        <div class="notice">{{ message }}</div>
      {% endif %}

      <form method="POST" style="margin-top:20px">
        <label>Sender's Account Name</label>
        <input name="sender_name"
               placeholder="Enter sender's name"
               maxlength="100" required>

        <label>Amount Deposited (₦)</label>
        <input name="amount"
               type="number" min="1000" step="1"
               placeholder="Enter amount" required>

        <button type="submit">SUBMIT DEPOSIT DETAILS</button>
      </form>

      <p class="muted" style="font-size:12px;line-height:1.8;margin-top:15px">
        Your request will remain pending until an administrator
        verifies the actual bank transfer. Submitting this form
        does not itself add money to your balance.
      </p>

      <a class="btn secondary" href="/dashboard">
        ← BACK TO DASHBOARD
      </a>
    """

    return page(
        render_template_string(content, message=message),
        "Deposit | PickEarn"
    )



@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    message = ""
    success = False

    if request.method == "POST":
        bank = request.form.get("bank_name", "").strip()
        account_name = request.form.get("account_name", "").strip()
        account_number = request.form.get("account_number", "").strip()
        amount_text = request.form.get("amount", "").strip()

        if not all([bank, account_name, account_number, amount_text]):
            message = "Please complete all withdrawal fields."
        elif len(bank) > 100 or len(account_name) > 100:
            message = "Please check your bank and account name."
        elif not account_number.isdigit() or not 6 <= len(account_number) <= 20:
            message = "Please enter a valid account number."
        else:
            try:
                amount = int(amount_text)

                if amount < 300:
                    message = "Minimum withdrawal is ₦300."
                else:
                    with get_db() as db:
                        db.execute("BEGIN IMMEDIATE")

                        user = db.execute(
                            "SELECT balance FROM users WHERE id=? FOR UPDATE",
                            (user_id,)
                        ).fetchone()

                        if not user:
                            message = "User account not found."
                        elif user["balance"] < amount:
                            message = (
                                f"Insufficient balance. Your available "
                                f"balance is ₦{user['balance']:,}."
                            )
                        else:
                            changed = db.execute("""
                                UPDATE users
                                SET balance=balance-?
                                WHERE id=? AND balance>=?
                            """, (amount, user_id, amount)).rowcount

                            if changed == 1:
                                db.execute("""
                                    INSERT INTO withdrawal_requests
                                    (user_id, bank_name, account_name,
                                     account_number, amount)
                                    VALUES (?, ?, ?, ?, ?)
                                """, (
                                    user_id, bank, account_name,
                                    account_number, amount
                                ))

                                db.execute("""
                                    INSERT INTO transactions
                                    (user_id, kind, amount, description)
                                    VALUES (?, 'withdrawal', ?, ?)
                                """, (
                                    user_id, -amount,
                                    "Withdrawal request pending approval"
                                ))

                                success = True
                                message = (
                                    "Withdrawal request submitted. "
                                    "Your money is reserved while admin reviews it."
                                )
                            else:
                                message = "Withdrawal could not be processed."

            except ValueError:
                message = "Enter a valid whole-number withdrawal amount."

    with get_db() as db:
        user = db.execute(
            "SELECT balance FROM users WHERE id=? FOR UPDATE",
            (user_id,)
        ).fetchone()

    content = """
      <style>
        .withdraw-card {
          margin:20px 0;padding:20px;text-align:center;
          border:1px solid #267343;border-radius:14px;
          background:linear-gradient(135deg,#123a22,#07130b);
        }
        .withdraw-balance {
          color:#29ff83;font-size:30px;font-weight:900;margin-top:10px;
        }
        .withdraw-message {
          padding:13px;margin:15px 0;border-radius:9px;
          background:#321416;color:#ffb6b6;font-size:12px;
          line-height:1.8;
        }
        .withdraw-message.success {
          background:#102d1b;color:#70ffab;
        }
        .withdraw-form label {
          display:block;margin:16px 0 8px;font-size:13px;
        }
        .withdraw-form input {
          width:100%;padding:14px;border-radius:10px;
          border:1px solid #244532;background:#07100b;
          color:white;font-size:14px;
        }
      </style>

      <h2 style="text-align:center;margin-top:20px">🏦 Withdraw Funds</h2>

      <div class="withdraw-card">
        <div class="muted">AVAILABLE BALANCE</div>
        <div class="withdraw-balance">
          ₦{{ "{:,}".format(balance) }}
        </div>
        <p class="muted" style="margin-top:10px">
          Minimum withdrawal: ₦300
        </p>
      </div>

      {% if message %}
        <div class="withdraw-message {{ 'success' if success else '' }}">
          {{ message }}
        </div>
      {% endif %}

      <form class="withdraw-form" method="POST">
        <label>Bank Name</label>
        <input name="bank_name" maxlength="100"
               placeholder="Enter your bank name" required>

        <label>Account Name</label>
        <input name="account_name" maxlength="100"
               placeholder="Account holder's name" required>

        <label>Account Number</label>
        <input name="account_number" inputmode="numeric"
               pattern="[0-9]{6,20}" maxlength="20"
               placeholder="Enter account number" required>

        <label>Withdrawal Amount (₦)</label>
        <input name="amount" type="number" min="300" step="1"
               placeholder="Minimum ₦300" required>

        <button type="submit">SUBMIT WITHDRAWAL REQUEST</button>
      </form>

      <p class="muted" style="font-size:12px;line-height:1.8;margin-top:18px">
        Your request will be sent to the administrator.
        The amount is reserved from your balance. If your
        request is rejected, the reserved amount will be refunded.
        Approval records a manual payment; it does not automatically
        transfer money to your bank.
      </p>

      <a class="btn secondary" href="/history">VIEW WITHDRAWAL HISTORY</a>
      <a class="btn secondary" href="/dashboard">← BACK TO DASHBOARD</a>
    """

    return page(
        render_template_string(
            content,
            message=message,
            success=success,
            balance=user["balance"] if user else 0
        ),
        "Withdraw | PickEarn"
    )


@app.route("/referrals")
def referrals():
    username = request.args.get("user", "").strip()

    with get_db() as db:
        user = db.execute(
            "SELECT username FROM users WHERE username=?",
            (username,)
        ).fetchone() if username else None

    if not user:
        content = """
          <h2>👥 PickEarn Referrals</h2>
          <p class="muted" style="margin-top:15px;line-height:1.9">
            Log in to get your personal referral link.
          </p>
          <a class="btn" href="/login">LOG IN</a>
          <a class="btn secondary" href="/register">CREATE ACCOUNT</a>
        """
        return page(content, "Referrals | PickEarn")

    referral_link = request.host_url.rstrip("/") + "/register?ref=" + user["username"]

    content = """
      <style>
        .ref-hero {
          margin-top:24px;
          padding:22px 15px;
          text-align:center;
          border:1px solid #267343;
          border-radius:16px;
          background:linear-gradient(135deg,#123a22,#07130b);
          box-shadow:0 0 22px #00ff6618;
        }
        .ref-icon { font-size:42px; }
        .reward {
          color:#29ff83;
          font-size:38px;
          font-weight:900;
          margin:12px 0;
          text-shadow:0 0 15px #29ff8344;
        }
        .ref-description {
          color:#a4b7a9;
          font-size:13px;
          line-height:1.9;
          margin-top:10px;
        }
        .link-box {
          margin-top:22px;
          padding:15px;
          border:1px solid #245236;
          border-radius:12px;
          background:#07100b;
        }
        .link-label {
          color:#9aafa0;
          font-size:12px;
          margin-bottom:10px;
        }
        .ref-link {
          width:100%;
          padding:12px;
          border:1px solid #244532;
          border-radius:8px;
          background:#0b1710;
          color:#29ff83;
          font-size:12px;
          overflow-wrap:anywhere;
          line-height:1.7;
        }
        .copy-button {
          width:100%;
          padding:14px;
          margin-top:12px;
          border:0;
          border-radius:9px;
          background:#29ff83;
          color:#031109;
          font-weight:bold;
          cursor:pointer;
          box-shadow:0 0 15px #29ff8322;
        }
        .ref-step {
          display:flex;
          gap:12px;
          padding:15px 0;
          border-bottom:1px solid #1a3021;
        }
        .step-number {
          min-width:32px;
          height:32px;
          display:flex;
          align-items:center;
          justify-content:center;
          border:1px solid #267343;
          border-radius:50%;
          color:#29ff83;
          font-weight:bold;
        }
        .ref-step h4 {
          font-size:14px;
          margin-bottom:6px;
        }
        .ref-step p {
          color:#9aafa0;
          font-size:12px;
          line-height:1.8;
        }
        .ref-notice {
          margin-top:20px;
          padding:13px;
          border:1px solid #4c4727;
          border-radius:10px;
          background:#19190f;
          color:#c8c5a6;
          font-size:11px;
          line-height:1.8;
        }
      </style>

      <div class="ref-hero">
        <div class="ref-icon">👥</div>
        <h2>Invite & Earn</h2>
        <div class="reward">50%</div>
        <p class="ref-description">
          Earn 50% of your friend’s activated plan cost as a referral reward.
          who registers through your link and activates a plan.
        </p>
      </div>

      <div class="link-box">
        <div class="link-label">YOUR PERSONAL REGISTRATION LINK</div>
        <div class="ref-link" id="refLink">{{ referral_link }}</div>
        <button class="copy-button" type="button" onclick="copyReferral()">
          🔗 COPY REFERRAL LINK
        </button>
        <p id="copyStatus" class="muted" style="margin-top:10px"></p>
      </div>

      <h3 style="margin-top:28px">How It Works ✨</h3>

      <div class="ref-step">
        <div class="step-number">1</div>
        <div>
          <h4>Share Your Link</h4>
          <p>Copy your personal registration link and share
          it with friends.</p>
        </div>
      </div>

      <div class="ref-step">
        <div class="step-number">2</div>
        <div>
          <h4>Your Friend Registers</h4>
          <p>Your friend opens your link and creates a
          PickEarn account.</p>
        </div>
      </div>

      <div class="ref-step">
        <div class="step-number">3</div>
        <div>
          <h4>Your Friend Activates a Plan</h4>
          <p>Your 50% referral reward is earned when your friend
          referral is verified and the friend activates an
          eligible plan, subject to the published terms.</p>
        </div>
      </div>

      <div class="ref-notice">
        <strong>Referral programme status</strong><br>
        Your referral link tracks friends who register using your link.
        attribution, plan activation verification, referral
        records, and reward payments have not yet been
        Rewards are credited to your wallet after successful eligible plan activation.
        or guaranteed.
      </div>

      <a class="btn secondary" href="/dashboard">
        ← BACK TO DASHBOARD
      </a>

      <script>
        function copyReferral() {
          const link = document.getElementById("refLink").textContent;
          const status = document.getElementById("copyStatus");

          if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(link).then(() => {
              status.textContent = "Referral link copied!";
            }).catch(() => fallbackCopy(link, status));
          } else {
            fallbackCopy(link, status);
          }
        }

        function fallbackCopy(link, status) {
          const input = document.createElement("textarea");
          input.value = link;
          input.style.position = "fixed";
          input.style.opacity = "0";
          document.body.appendChild(input);
          input.select();

          try {
            const copied = document.execCommand("copy");
            status.textContent = copied
              ? "Referral link copied!"
              : "Please copy the link manually.";
          } catch (error) {
            status.textContent = "Please copy the link manually.";
          }

          input.remove();
        }
      </script>
    """

    return page(
        render_template_string(content, referral_link=referral_link),
        "Referrals | PickEarn"
    )

from functools import wraps
from flask import render_template_string, request, redirect, url_for, session
import secrets

def init_admin_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS deposit_requests (
                id BIGSERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                sender_name TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id BIGSERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                bank_name TEXT NOT NULL,
                account_name TEXT NOT NULL,
                account_number TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                link TEXT NOT NULL,
                reward_plan1 INTEGER NOT NULL,
                reward_plan3 INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_csrf():
    token = session.get("admin_csrf")
    supplied = request.form.get("csrf_token", "")
    return bool(token and secrets.compare_digest(token, supplied))

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    message = ""
    if request.method == "POST":
        password = request.form.get("password", "")
        expected = os.environ.get("PICKEARN_ADMIN_PASSWORD", "PickEarn@50")
        if not expected:
            message = "Admin password is not configured. Set PICKEARN_ADMIN_PASSWORD in Termux."
        elif secrets.compare_digest(password, expected):
            session.clear()
            session["is_admin"] = True
            session["admin_csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("admin_dashboard"))
        else:
            message = "Incorrect admin password."

    return page(render_template_string("""
      <h2>🔐 PickEarn Admin Login</h2>
      {% if message %}<div class="notice">{{ message }}</div>{% endif %}
      <form method="post">
        <label>Admin Password</label>
        <input type="password" name="password" required>
        <button type="submit">LOGIN AS ADMIN</button>
      </form>
      <a class="btn secondary" href="/welcome">BACK TO WEBSITE</a>
    """, message=message), "Admin Login | PickEarn")

@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    if not admin_csrf():
        return "Invalid request token.", 400
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    with get_db() as db:
        total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = db.execute(
            "SELECT COUNT(*) FROM users WHERE active_plan IS NOT NULL"
        ).fetchone()[0]
        pending_deposits = db.execute(
            "SELECT COUNT(*) FROM deposit_requests WHERE status='pending'"
        ).fetchone()[0]
        pending_withdrawals = db.execute(
            "SELECT COUNT(*) FROM withdrawal_requests WHERE status='pending'"
        ).fetchone()[0]
        users = db.execute("""
            SELECT id, fullname, username, email, balance, active_plan
            FROM users ORDER BY id DESC LIMIT 50
        """).fetchall()
        deposits = db.execute("""
            SELECT d.*, u.username FROM deposit_requests d
            JOIN users u ON u.id=d.user_id ORDER BY d.id DESC LIMIT 50
        """).fetchall()
        withdrawals = db.execute("""
            SELECT w.*, u.username FROM withdrawal_requests w
            JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 50
        """).fetchall()
        tasks = db.execute(
            "SELECT * FROM tasks ORDER BY id DESC"
        ).fetchall()

    content = """
    <style>
      .admin-stat{padding:15px;margin:10px 0;background:#102318;
        border:1px solid #267343;border-radius:12px}
      .admin-stat strong{display:block;color:#29ff83;font-size:25px}
      .admin-section{margin-top:28px;padding:15px;background:#0b1510;
        border:1px solid #244532;border-radius:12px;overflow-wrap:anywhere}
      .admin-item{padding:13px 0;border-bottom:1px solid #244532;
        font-size:12px;line-height:1.8}
      .admin-item form{display:inline-block;margin:5px 5px 0 0}
      .small-btn{padding:9px 12px;width:auto;margin:4px 0}
      .admin-section input,.admin-section textarea{
        width:100%;margin:7px 0 13px;padding:12px;background:#07100b;
        color:white;border:1px solid #244532;border-radius:8px}
      .admin-section textarea{min-height:90px}
      .status{color:#29ff83}
    </style>

    <h2>🛡️ PickEarn Admin Dashboard</h2>
    <a href="/admin/submissions" style="
      display:block;
      width:100%;
      box-sizing:border-box;
      padding:20px;
      margin:20px 0;
      text-align:center;
      background:linear-gradient(135deg,#29ff83,#00b85c);
      color:#04150b;
      font-size:17px;
      font-weight:900;
      border-radius:14px;
      text-decoration:none;
      box-shadow:0 0 20px rgba(41,255,131,.45);
    ">📝 REVIEW TASK SUBMISSIONS</a>
    <p class="muted">Private administration panel</p>

    <div class="admin-stat">Total Registered Users
      <strong>{{ total_users }}</strong></div>
    <div class="admin-stat">Users With Active Plans
      <strong>{{ active_users }}</strong></div>
    <div class="admin-stat">Pending Deposits
      <strong>{{ pending_deposits }}</strong></div>
    <div class="admin-stat">Pending Withdrawals
      <strong>{{ pending_withdrawals }}</strong></div>

    <div class="admin-section">
      <h3>➕ Create New Task</h3>
      <form method="post" action="/admin/task/create">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">
        <label>Task Title</label>
        <input name="title" maxlength="120" required>
        <label>Task Description</label>
        <textarea name="description" maxlength="2000" required></textarea>
        <label>Task Link</label>
        <input name="link" type="url" maxlength="1000" required>
        <label>Plan 1 Reward (₦)</label>
        <input name="reward_plan1" type="number" min="0" step="1" required>
        <label>Plan 3 Reward (₦)</label>
        <input name="reward_plan3" type="number" min="0" step="1" required>
        <button type="submit">CREATE TASK</button>
      </form>
    </div>

    <div class="admin-section">
      <h3>📋 Created Tasks</h3>
      {% for t in tasks %}
      <div class="admin-item">
        <strong>{{ t.title }}</strong><br>
        Plan 1: ₦{{ t.reward_plan1 }} |
        Plan 3: ₦{{ t.reward_plan3 }}<br>
        <a href="{{ t.link }}" target="_blank" rel="noopener">Open task link</a><br>
        Status: {{ 'Active' if t.is_active else 'Inactive' }}
        <form method="post" action="/admin/task/toggle">
          <input type="hidden" name="csrf_token" value="{{ csrf }}">
          <input type="hidden" name="task_id" value="{{ t.id }}">
          <button class="small-btn" type="submit">
            {{ 'DEACTIVATE' if t.is_active else 'ACTIVATE' }}
          </button>
        </form>
      </div>
      {% else %}<p class="muted">No tasks created yet.</p>{% endfor %}
    </div>

    <div class="admin-section">
      <h3>💳 Deposit Requests</h3>
      {% for d in deposits %}
      <div class="admin-item">
        User: {{ d.username }} | ₦{{ d.amount }}<br>
        Sender: {{ d.sender_name }}<br>
        Status: <span class="status">{{ d.status }}</span><br>
        {% if d.status == 'pending' %}
        <form method="post" action="/admin/deposit/review">
          <input type="hidden" name="csrf_token" value="{{ csrf }}">
          <input type="hidden" name="request_id" value="{{ d.id }}">
          <button class="small-btn" name="decision" value="approve">APPROVE VERIFIED DEPOSIT</button>
          <button class="small-btn" name="decision" value="reject">REJECT</button>
        </form>
        {% endif %}
      </div>
      {% else %}<p class="muted">No deposit requests yet.</p>{% endfor %}
    </div>

    <div class="admin-section">
      <h3>🏦 Withdrawal Requests</h3>
      {% for w in withdrawals %}
      <div class="admin-item">
        User: {{ w.username }} | ₦{{ w.amount }}<br>
        Bank: {{ w.bank_name }}<br>
        Account: {{ w.account_name }} — {{ w.account_number }}<br>
        Status: <span class="status">{{ w.status }}</span><br>
        {% if w.status == 'pending' %}
        <form method="post" action="/admin/withdrawal/review">
          <input type="hidden" name="csrf_token" value="{{ csrf }}">
          <input type="hidden" name="request_id" value="{{ w.id }}">
          <button class="small-btn" name="decision" value="paid">MARK PAID</button>
          <button class="small-btn" name="decision" value="reject">REJECT AND REFUND</button>
        </form>
        {% endif %}
      </div>
      {% else %}<p class="muted">No withdrawal requests yet.</p>{% endfor %}
    </div>

    <div class="admin-section">
      <h3>👥 Registered Users (Latest 50)</h3>
      {% for u in users %}
      <div class="admin-item">
        {{ u.fullname }} (@{{ u.username }})<br>
        {{ u.email }}<br>
        Balance: ₦{{ u.balance }} | Plan: {{ u.active_plan or 'None' }}
      </div>
      {% endfor %}
    </div>

    <form method="post" action="/admin/logout">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">
      <button type="submit">ADMIN LOGOUT</button>
    </form>
    <a class="btn secondary" href="/dashboard">USER WEBSITE</a>
    """
    return page(render_template_string(
        content, total_users=total_users, active_users=active_users,
        pending_deposits=pending_deposits,
        pending_withdrawals=pending_withdrawals,
        users=users, deposits=deposits, withdrawals=withdrawals,
        tasks=tasks, csrf=session["admin_csrf"]
    ), "Admin Dashboard | PickEarn")

@app.route("/admin/task/create", methods=["POST"])
@admin_required
def admin_task_create():
    if not admin_csrf():
        return "Invalid request token.", 400
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    link = request.form.get("link", "").strip()
    try:
        reward1 = int(request.form.get("reward_plan1", ""))
        reward3 = int(request.form.get("reward_plan3", ""))
    except ValueError:
        return "Invalid task reward.", 400
    if (not title or not description or not link or
        len(title) > 120 or len(description) > 2000 or
        reward1 < 0 or reward3 < 0 or
        not link.startswith(("https://", "http://"))):
        return "Please check the task details.", 400
    with get_db() as db:
        db.execute("""
            INSERT INTO tasks
            (title, description, link, reward_plan1, reward_plan3)
            VALUES (?, ?, ?, ?, ?)
        """, (title, description, link, reward1, reward3))
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/task/toggle", methods=["POST"])
@admin_required
def admin_task_toggle():
    if not admin_csrf():
        return "Invalid request token.", 400
    try:
        task_id = int(request.form.get("task_id", ""))
    except ValueError:
        return "Invalid task.", 400
    with get_db() as db:
        db.execute(
            "UPDATE tasks SET is_active=1-is_active WHERE id=?",
            (task_id,)
        )
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/deposit/review", methods=["POST"])
@admin_required
def admin_deposit_review():
    if not admin_csrf():
        return "Invalid request token.", 400
    decision = request.form.get("decision")
    try:
        request_id = int(request.form.get("request_id", ""))
    except ValueError:
        return "Invalid request.", 400
    if decision not in ("approve", "reject"):
        return "Invalid decision.", 400

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM deposit_requests WHERE id=? AND status='pending'",
            (request_id,)
        ).fetchone()
        if row:
            status = "approved" if decision == "approve" else "rejected"
            db.execute("""
                UPDATE deposit_requests
                SET status=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?
            """, (status, request_id))
            if decision == "approve":
                db.execute(
                    "UPDATE users SET balance=balance+? WHERE id=?",
                    (row["amount"], row["user_id"])
                )
                db.execute("""
                    INSERT INTO transactions
                    (user_id, kind, amount, description)
                    VALUES (?, 'deposit', ?, 'Admin-approved deposit')
                """, (row["user_id"], row["amount"]))
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/withdrawal/review", methods=["POST"])
@admin_required
def admin_withdrawal_review():
    if not admin_csrf():
        return "Invalid request token.", 400
    decision = request.form.get("decision")
    try:
        request_id = int(request.form.get("request_id", ""))
    except ValueError:
        return "Invalid request.", 400
    if decision not in ("paid", "reject"):
        return "Invalid decision.", 400

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM withdrawal_requests WHERE id=? AND status='pending'",
            (request_id,)
        ).fetchone()
        if row:
            status = "paid" if decision == "paid" else "rejected"
            db.execute("""
                UPDATE withdrawal_requests
                SET status=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?
            """, (status, request_id))
            if decision == "reject":
                db.execute(
                    "UPDATE users SET balance=balance+? WHERE id=?",
                    (row["amount"], row["user_id"])
                )
                db.execute("""
                    INSERT INTO transactions
                    (user_id, kind, amount, description)
                    VALUES (?, 'withdrawal_refund', ?, 'Rejected withdrawal refund')
                """, (row["user_id"], row["amount"]))
    return redirect(url_for("admin_dashboard"))


@app.route("/tasks")
def user_tasks():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    with get_db() as db:
        user = db.execute(
            "SELECT username, active_plan FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        tasks = db.execute("""
            SELECT t.*,
                (SELECT s.status FROM task_submissions s
                 WHERE s.task_id=t.id AND s.user_id=?
                 ORDER BY s.id DESC LIMIT 1) AS last_status
            FROM tasks t
            WHERE t.is_active=1
            ORDER BY t.id DESC
        """, (user_id,)).fetchall()

        submissions = db.execute("""
            SELECT s.id, s.task_id, s.proof, s.status,
                   s.created_at, t.title, s.reward
            FROM task_submissions s
            JOIN tasks t ON t.id=s.task_id
            WHERE s.user_id=?
            ORDER BY s.id DESC
        """, (user_id,)).fetchall()

    if user["active_plan"] == "PLAN 1":
        reward_column = "reward_plan1"
    elif user["active_plan"] == "PLAN 3":
        reward_column = "reward_plan3"
    else:
        reward_column = None

    content = """
    <style>
      .task-card {
        background:#0b1710;border:1px solid #267343;
        border-radius:13px;padding:17px;margin:16px 0;
      }
      .task-reward {
        color:#29ff83;font-size:23px;font-weight:bold;
        margin:10px 0;
      }
      .task-card input {
        width:100%;padding:12px;margin:8px 0 12px;
        background:#07100b;color:white;
        border:1px solid #244532;border-radius:8px;
      }
      .task-status {
        color:#29ff83;font-weight:bold;
        font-size:12px;
      }
    </style>

    <h2>🎯 Available Tasks</h2>
    <p class="muted">Username: @{{ username }}</p>

    {% if not reward_column %}
      <div class="notice">
        Activate a plan before accessing tasks.
      </div>
      <a class="btn" href="/dashboard">VIEW PLANS</a>
    {% else %}
      {% for t in tasks %}
        {% set reward = t[reward_column] %}
        {% if t.last_status != 'approved' and t.last_status != 'pending' %}
        <div class="task-card">
          <h3>{{ t.title }}</h3>
          <p class="muted" style="line-height:1.8;margin-top:10px">
            {{ t.description }}
          </p>
          <div class="task-reward">₦{{ "{:,}".format(reward) }}</div>

          <a class="btn" href="{{ t.link }}"
             target="_blank" rel="noopener">
             OPEN TASK LINK ↗
          </a>

          <form method="post" action="/tasks/submit">
            <input type="hidden" name="csrf_token" value="{{ csrf }}">
            <input type="hidden" name="task_id" value="{{ t.id }}">

            <label>Your PickEarn Username</label>
            <input value="{{ username }}" readonly>

            <label>Proof / Completed Task Details</label>
            <input name="proof" maxlength="1000"
                   placeholder="Enter your proof or reference"
                   required>

            <button type="submit">SUBMIT COMPLETED TASK</button>
          </form>
        </div>
        {% elif t.last_status == 'pending' %}
          <div class="task-card">
            <h3>{{ t.title }}</h3>
            <p class="task-status">⏳ WAITING FOR ADMIN REVIEW</p>
          </div>
        {% endif %}
      {% else %}
        <p class="muted">No tasks are available right now.</p>
      {% endfor %}
    {% endif %}

    <div class="task-card">
      <h3>📜 Your Task Submissions</h3>
      {% for s in submissions %}
        <div style="padding:12px 0;border-bottom:1px solid #244532">
          <strong>{{ s.title }}</strong><br>
          Status: <span class="task-status">{{ s.status|upper }}</span><br>
          {% if s.status == 'approved' %}
            Reward: ₦{{ "{:,}".format(s.reward) }}
          {% elif s.status == 'rejected' %}
            <span class="muted">Rejected. You can try this task again.</span>
          {% endif %}
          <br><small class="muted">{{ s.created_at }}</small>
        </div>
      {% else %}
        <p class="muted">You have not submitted any tasks.</p>
      {% endfor %}
    </div>

    <a class="btn secondary" href="/dashboard">← DASHBOARD</a>
    """
    return page(render_template_string(
        content,
        username=user["username"],
        tasks=tasks,
        submissions=submissions,
        reward_column=reward_column,
        csrf=session["task_csrf"]
    ), "Tasks | PickEarn")


@app.route("/tasks/submit", methods=["POST"])
def submit_task():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    if not session.get("task_csrf") or not secrets.compare_digest(
        session["task_csrf"], request.form.get("csrf_token", "")
    ):
        return "Invalid request token. Reload the tasks page.", 400

    try:
        task_id = int(request.form.get("task_id", ""))
    except ValueError:
        return "Invalid task.", 400

    proof = request.form.get("proof", "").strip()
    if not proof or len(proof) > 1000:
        return "Enter valid task proof.", 400

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")

        user = db.execute(
            "SELECT active_plan FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

        task = db.execute("""
            SELECT * FROM tasks WHERE id=? AND is_active=1
        """, (task_id,)).fetchone()

        if not user or not user["active_plan"] or not task:
            return "This task is unavailable or your plan is inactive.", 400

        if user["active_plan"] == "PLAN 1":
            reward = task["reward_plan1"]
        elif user["active_plan"] == "PLAN 3":
            reward = task["reward_plan3"]
        else:
            return "Your plan is not eligible for this task.", 400

        previous = db.execute("""
            SELECT status FROM task_submissions
            WHERE user_id=? AND task_id=?
            ORDER BY id DESC LIMIT 1
        """, (user_id, task_id)).fetchone()

        if previous and previous["status"] in ("pending", "approved"):
            return "You already submitted this task.", 400

        db.execute("""
            INSERT INTO task_submissions
            (user_id, task_id, proof, reward, status)
            VALUES (?, ?, ?, ?, 'pending')
        """, (user_id, task_id, proof, reward))

        session["task_csrf"] = secrets.token_urlsafe(32)

    return redirect(url_for("user_tasks"))


@app.route("/admin/submissions")
@admin_required
def admin_submissions():
    with get_db() as db:
        submissions = db.execute("""
            SELECT s.*, u.username, u.fullname, t.title
            FROM task_submissions s
            JOIN users u ON u.id=s.user_id
            JOIN tasks t ON t.id=s.task_id
            ORDER BY
              CASE WHEN s.status='pending' THEN 0 ELSE 1 END,
              s.id DESC
        """).fetchall()

    content = """
    <style>
      .submission-card {
        margin:15px 0;padding:16px;background:#0b1710;
        border:1px solid #267343;border-radius:12px;
        overflow-wrap:anywhere;
      }
      .submission-card form{display:inline-block;margin:7px 5px 0 0}
      .submission-card button{width:auto;padding:10px}
    </style>

    <h2>📝 Task Submissions</h2>

    {% for s in submissions %}
      <div class="submission-card">
        <h3>{{ s.title }}</h3>
        <p style="margin-top:10px">
          User: <strong>{{ s.username }}</strong><br>
          Full name: {{ s.fullname }}<br>
          Reward: <strong style="color:#29ff83">
            ₦{{ "{:,}".format(s.reward) }}
          </strong><br>
          Proof: {{ s.proof }}<br>
          Status: <strong>{{ s.status|upper }}</strong><br>
          Submitted: {{ s.created_at }}
        </p>

        {% if s.status == 'pending' %}
        <form method="post" action="/admin/submissions/review">
          <input type="hidden" name="csrf_token" value="{{ csrf }}">
          <input type="hidden" name="submission_id" value="{{ s.id }}">
          <button name="decision" value="approve">APPROVE & PAY REWARD</button>
          <button name="decision" value="reject">REJECT TASK</button>
        </form>
        {% endif %}
      </div>
    {% else %}
      <p class="muted">No task submissions yet.</p>
    {% endfor %}

    <a class="btn secondary" href="/admin">← ADMIN DASHBOARD</a>
    """

    return page(render_template_string(
        content, submissions=submissions,
        csrf=session["admin_csrf"]
    ), "Task Submissions | PickEarn")


@app.route("/admin/submissions/review", methods=["POST"])
@admin_required
def admin_submission_review():
    if not admin_csrf():
        return "Invalid admin request token.", 400

    decision = request.form.get("decision")
    try:
        submission_id = int(request.form.get("submission_id", ""))
    except ValueError:
        return "Invalid submission.", 400

    if decision not in ("approve", "reject"):
        return "Invalid decision.", 400

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")

        submission = db.execute("""
            SELECT * FROM task_submissions
            WHERE id=? AND status='pending'
        """, (submission_id,)).fetchone()

        if submission:
            if decision == "approve":
                changed = db.execute("""
                    UPDATE task_submissions
                    SET status='approved', reviewed_at=CURRENT_TIMESTAMP
                    WHERE id=? AND status='pending'
                """, (submission_id,)).rowcount

                if changed == 1:
                    db.execute(
                        "UPDATE users SET balance=balance+? WHERE id=?",
                        (submission["reward"], submission["user_id"])
                    )
                    db.execute("""
                        INSERT INTO transactions
                        (user_id, kind, amount, description)
                        VALUES (?, 'task_reward', ?, ?)
                    """, (
                        submission["user_id"],
                        submission["reward"],
                        "Approved task reward"
                    ))
            else:
                db.execute("""
                    UPDATE task_submissions
                    SET status='rejected', reviewed_at=CURRENT_TIMESTAMP
                    WHERE id=? AND status='pending'
                """, (submission_id,))

    return redirect(url_for("admin_submissions"))


def init_task_submission_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS task_submissions (
                id BIGSERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                proof TEXT NOT NULL,
                reward INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(task_id) REFERENCES tasks(id)
            )
        """)

init_db()
init_admin_db()
init_task_submission_db()

@app.before_request
def ensure_task_csrf():
    if session.get("user_id") and not session.get("task_csrf"):
        session["task_csrf"] = secrets.token_urlsafe(32)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

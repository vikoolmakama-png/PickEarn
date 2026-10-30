from functools import wraps
from flask import render_template_string, request, redirect, url_for, session
import secrets
import sqlite3

def init_admin_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS deposit_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        expected = os.environ.get("PICKEARN_ADMIN_PASSWORD", "")
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

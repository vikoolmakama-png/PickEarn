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

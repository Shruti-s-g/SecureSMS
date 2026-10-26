from datetime import date
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

import click
from flask import (
    Flask, abort, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, instance_relative_config=True)
Path(app.instance_path).mkdir(parents=True, exist_ok=True)

# Keep the key across restarts so existing sessions remain valid. Never publish this file.
key_path = Path(app.instance_path) / "secret_key"
if not key_path.exists():
    key_path.write_text(secrets.token_hex(32), encoding="utf-8")
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
app.config.update(
    SECRET_KEY=key_path.read_text(encoding="utf-8"),
    DATABASE=str(Path(app.instance_path) / "students.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
# Set SESSION_COOKIE_SECURE=True when running behind HTTPS in a deployment.


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        existing = db.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()
        # Earlier versions allowed only admin/student roles. Rebuild this table
        # once, preserving IDs so all existing student and log links still work.
        if existing and "'teacher'" not in existing["sql"]:
            db.commit()
            db.execute("PRAGMA foreign_keys = OFF")
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("""CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'student', 'teacher'))
                )""")
                db.execute("INSERT INTO users_new SELECT id, username, email, password_hash, role FROM users")
                db.execute("DROP TABLE users")
                db.execute("ALTER TABLE users_new RENAME TO users")
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.execute("PRAGMA foreign_keys = ON")
        db.executescript((BASE_DIR / "schema.sql").read_text(encoding="utf-8"))
        problems = db.execute("PRAGMA foreign_key_check").fetchall()
        if problems:
            raise RuntimeError("Database links need repair; restore your backup.")


@app.cli.command("init-db")
def init_db_command():
    """Create tables without erasing existing records."""
    init_db()
    click.echo("Database ready.")


@app.cli.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--email", prompt=True)
@click.password_option(confirmation_prompt=True)
def create_admin_command(username, email, password):
    """Create an admin account through the terminal only."""
    username = username.strip()
    email = email.strip().lower()
    error = validate_account(username, email, password)
    if error:
        raise click.ClickException(error)
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (username, email, generate_password_hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise click.ClickException("Username or email already exists.") from None
    click.echo("Admin created. You can log in now.")


def log_event(event_type, details, user_id=None):
    db = get_db()
    db.execute(
        "INSERT INTO security_logs (user_id, event_type, details) VALUES (?, ?, ?)",
        (user_id, event_type, details),
    )
    db.commit()


@app.before_request
def load_user_and_check_csrf():
    user_id = session.get("user_id")
    g.user = get_db().execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone() if isinstance(user_id, int) else None
    if user_id is not None and g.user is None:
        session.clear()

    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="Invalid form token. Refresh the page and try again.")


@app.context_processor
def include_csrf_token():
    def token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]
    return {"csrf_token": token}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            log_event("unauthorized_access", f"Blocked admin URL: {request.path}", g.user["id"])
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def teacher_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "teacher":
            log_event("unauthorized_access", f"Blocked teacher URL: {request.path}", g.user["id"])
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def validate_account(username, email, password):
    if not re.fullmatch(r"[A-Za-z0-9_]{5,15}", username):
        return "Username must be 5–15 letters, digits, or underscores."
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return "Enter a valid email address."
    if len(password) < 8:
        return "Password must have at least 8 characters."
    return None


def student_form_data():
    full_name = request.form.get("full_name", "").strip()
    roll_number = request.form.get("roll_number", "").strip()
    course = request.form.get("course", "").strip()
    year_text = request.form.get("year", "").strip()
    if not (2 <= len(full_name) <= 80):
        return None, "Full name must be 2–80 characters."
    if not re.fullmatch(r"[A-Za-z0-9/-]{2,30}", roll_number):
        return None, "Roll number must be 2–30 letters, digits, / or -."
    if not (2 <= len(course) <= 80):
        return None, "Course must be 2–80 characters."
    if not year_text.isdigit() or not (1 <= int(year_text) <= 8):
        return None, "Year must be a number from 1 to 8."
    return (full_name, roll_number, course, int(year_text)), None


def teacher_form_data():
    full_name = request.form.get("full_name", "").strip()
    course = request.form.get("course", "").strip()
    subject = request.form.get("subject", "").strip()
    if not (2 <= len(full_name) <= 80):
        return None, "Teacher name must be 2–80 characters."
    if not (2 <= len(course) <= 80):
        return None, "Course must be 2–80 characters and match the student course."
    if not (2 <= len(subject) <= 80):
        return None, "Subject must be 2–80 characters."
    return (full_name, course, subject), None


@app.route("/")
def index():
    if g.user is None:
        return redirect(url_for("login"))
    destinations = {"admin": "admin_dashboard", "teacher": "teacher_dashboard", "student": "student_dashboard"}
    return redirect(url_for(destinations[g.user["role"]]))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = validate_account(username, email, password)
        data, student_error = student_form_data()
        if error or student_error:
            flash(error or student_error, "error")
        else:
            db = get_db()
            try:
                with db:
                    cursor = db.execute(
                        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                        (username, email, generate_password_hash(password)),
                    )
                    db.execute(
                        "INSERT INTO students (user_id, full_name, roll_number, course, year) VALUES (?, ?, ?, ?, ?)",
                        (cursor.lastrowid, *data),
                    )
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username, email, or roll number already exists.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            log_event("failed_login", "Incorrect login credentials", user["id"] if user else None)
            flash("Incorrect email or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def student_dashboard():
    if g.user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    if g.user["role"] == "teacher":
        return redirect(url_for("teacher_dashboard"))
    student = get_db().execute(
        "SELECT s.*, u.email, u.username FROM students s JOIN users u ON u.id = s.user_id WHERE s.user_id = ?",
        (g.user["id"],)
    ).fetchone()
    if student is None:
        abort(404)
    return render_template("student_dashboard.html", student=student)


@app.route("/students/<int:student_id>")
@login_required
def view_student(student_id):
    student = get_db().execute(
        "SELECT s.*, u.email, u.username FROM students s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
        (student_id,),
    ).fetchone()
    if student is None:
        abort(404)
    if g.user["role"] != "admin" and student["user_id"] != g.user["id"]:
        log_event("unauthorized_access", f"Blocked student record ID {student_id}", g.user["id"])
        abort(403)
    return render_template("student_dashboard.html", student=student)


@app.route("/attendance/my-report")
@login_required
def my_attendance():
    if g.user["role"] != "student":
        return redirect(url_for("index"))
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE user_id = ?", (g.user["id"],)).fetchone()
    if student is None:
        abort(404)
    records = db.execute("""SELECT a.attendance_date, a.status, t.subject, t.full_name AS teacher_name
        FROM attendance a JOIN teachers t ON t.id = a.teacher_id
        WHERE a.student_id = ? ORDER BY a.attendance_date DESC, t.subject""", (student["id"],)).fetchall()
    return render_template("attendance_report.html", student=student, records=records,
                           present=sum(r["status"] == "Present" for r in records))


@app.route("/admin")
@admin_required
def admin_dashboard():
    students = get_db().execute(
        "SELECT s.*, u.email, u.username FROM students s JOIN users u ON u.id = s.user_id ORDER BY s.id DESC"
    ).fetchall()
    return render_template("admin_dashboard.html", students=students)


@app.route("/admin/students/new", methods=["GET", "POST"])
@admin_required
def add_student():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = validate_account(username, email, password)
        data, student_error = student_form_data()
        if error or student_error:
            flash(error or student_error, "error")
        else:
            db = get_db()
            try:
                with db:
                    cursor = db.execute(
                        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                        (username, email, generate_password_hash(password)),
                    )
                    db.execute(
                        "INSERT INTO students (user_id, full_name, roll_number, course, year) VALUES (?, ?, ?, ?, ?)",
                        (cursor.lastrowid, *data),
                    )
                flash("Student added.", "success")
                return redirect(url_for("admin_dashboard"))
            except sqlite3.IntegrityError:
                flash("Username, email, or roll number already exists.", "error")
    return render_template("student_form.html", student=None)


@app.route("/admin/students/<int:student_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_student(student_id):
    student = get_db().execute(
        "SELECT * FROM students WHERE id = ?", (student_id,)
    ).fetchone()
    if student is None:
        abort(404)
    if request.method == "POST":
        data, error = student_form_data()
        if error:
            flash(error, "error")
        else:
            try:
                db = get_db()
                db.execute(
                    "UPDATE students SET full_name = ?, roll_number = ?, course = ?, year = ? WHERE id = ?",
                    (*data, student_id),
                )
                db.commit()
                flash("Student updated.", "success")
                return redirect(url_for("admin_dashboard"))
            except sqlite3.IntegrityError:
                flash("That roll number is already in use.", "error")
    return render_template("student_form.html", student=student)


@app.post("/admin/students/<int:student_id>/delete")
@admin_required
def delete_student(student_id):
    db = get_db()
    student = db.execute("SELECT user_id FROM students WHERE id = ?", (student_id,)).fetchone()
    if student is None:
        abort(404)
    db.execute("DELETE FROM users WHERE id = ?", (student["user_id"],))
    db.commit()  # The related student row is deleted by ON DELETE CASCADE.
    flash("Student and login account deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/teachers")
@admin_required
def admin_teachers():
    teachers = get_db().execute("""SELECT t.*, u.username, u.email FROM teachers t
        JOIN users u ON u.id = t.user_id ORDER BY t.full_name""").fetchall()
    return render_template("teachers.html", teachers=teachers)


@app.route("/admin/teachers/new", methods=["GET", "POST"])
@admin_required
def add_teacher():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = validate_account(username, email, password)
        data, teacher_error = teacher_form_data()
        if error or teacher_error:
            flash(error or teacher_error, "error")
        else:
            db = get_db()
            try:
                with db:
                    cursor = db.execute(
                        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                        (username, email, generate_password_hash(password)),
                    )
                    db.execute(
                        "INSERT INTO teachers (user_id, full_name, course, subject) VALUES (?, ?, ?, ?)",
                        (cursor.lastrowid, *data),
                    )
                flash("Teacher account created.", "success")
                return redirect(url_for("admin_teachers"))
            except sqlite3.IntegrityError:
                flash("Username or email already exists.", "error")
    return render_template("teacher_form.html", teacher=None)


@app.route("/admin/teachers/<int:teacher_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_teacher(teacher_id):
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if teacher is None:
        abort(404)
    if request.method == "POST":
        data, error = teacher_form_data()
        has_attendance = db.execute(
            "SELECT 1 FROM attendance WHERE teacher_id = ? LIMIT 1", (teacher_id,)
        ).fetchone()
        if has_attendance and (data is not None and (data[1] != teacher["course"] or data[2] != teacher["subject"])):
            error = "Course and subject cannot change after attendance has been marked."
        if error:
            flash(error, "error")
        else:
            db.execute("UPDATE teachers SET full_name = ?, course = ?, subject = ? WHERE id = ?", (*data, teacher_id))
            db.commit()
            flash("Teacher updated.", "success")
            return redirect(url_for("admin_teachers"))
    return render_template("teacher_form.html", teacher=teacher)


@app.post("/admin/teachers/<int:teacher_id>/delete")
@admin_required
def delete_teacher(teacher_id):
    db = get_db()
    teacher = db.execute("SELECT user_id FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if teacher is None:
        abort(404)
    if db.execute("SELECT 1 FROM attendance WHERE teacher_id = ? LIMIT 1", (teacher_id,)).fetchone():
        flash("This teacher has attendance records and cannot be deleted.", "error")
    else:
        db.execute("DELETE FROM users WHERE id = ?", (teacher["user_id"],))
        db.commit()
        flash("Teacher deleted.", "success")
    return redirect(url_for("admin_teachers"))


@app.route("/teacher")
@teacher_required
def teacher_dashboard():
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE user_id = ?", (g.user["id"],)).fetchone()
    if teacher is None:
        abort(404)
    day = request.args.get("day", date.today().isoformat())
    try:
        selected_date = date.fromisoformat(day)
        if selected_date.isoformat() != day or selected_date > date.today():
            raise ValueError()
    except ValueError:
        abort(400, description="Choose a valid date up to today.")
    students = db.execute("""SELECT s.id, s.full_name, s.roll_number, a.status
        FROM students s LEFT JOIN attendance a ON a.student_id = s.id
        AND a.teacher_id = ? AND a.attendance_date = ?
        WHERE s.course = ? ORDER BY s.roll_number""",
        (teacher["id"], day, teacher["course"])).fetchall()
    return render_template("teacher_dashboard.html", teacher=teacher, students=students,
                           day=day, today=date.today().isoformat())


@app.post("/teacher/attendance/<int:student_id>")
@teacher_required
def mark_attendance(student_id):
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE user_id = ?", (g.user["id"],)).fetchone()
    if teacher is None:
        abort(404)
    student = db.execute("SELECT id, course FROM students WHERE id = ?", (student_id,)).fetchone()
    if student is None:
        abort(404)
    if student["course"] != teacher["course"]:
        log_event("unauthorized_access", f"Blocked attendance for student ID {student_id}", g.user["id"])
        abort(403)
    day = request.form.get("day", "")
    status = request.form.get("status", "")
    try:
        parsed = date.fromisoformat(day)
        if parsed.isoformat() != day or parsed > date.today():
            raise ValueError()
    except ValueError:
        abort(400, description="Invalid attendance date.")
    if status not in {"Present", "Absent"}:
        abort(400, description="Invalid attendance status.")
    db.execute("""INSERT INTO attendance (student_id, teacher_id, attendance_date, status)
        VALUES (?, ?, ?, ?) ON CONFLICT(student_id, teacher_id, attendance_date)
        DO UPDATE SET status = excluded.status, marked_at = datetime('now')""",
        (student_id, teacher["id"], day, status))
    db.commit()
    flash("Attendance saved.", "success")
    return redirect(url_for("teacher_dashboard", day=day))


@app.route("/admin/attendance")
@admin_required
def admin_attendance():
    students = get_db().execute("""SELECT s.id, s.full_name, s.roll_number, s.course,
        COUNT(a.id) AS total, COALESCE(SUM(a.status = 'Present'), 0) AS present
        FROM students s LEFT JOIN attendance a ON a.student_id = s.id
        GROUP BY s.id ORDER BY s.roll_number""").fetchall()
    return render_template("admin_attendance.html", students=students)


@app.route("/admin/attendance/<int:student_id>")
@admin_required
def admin_student_attendance(student_id):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if student is None:
        abort(404)
    records = db.execute("""SELECT a.attendance_date, a.status, t.subject, t.full_name AS teacher_name
        FROM attendance a JOIN teachers t ON t.id = a.teacher_id
        WHERE a.student_id = ? ORDER BY a.attendance_date DESC, t.subject""", (student_id,)).fetchall()
    return render_template("attendance_report.html", student=student, records=records,
                           present=sum(r["status"] == "Present" for r in records))


@app.route("/admin/logs")
@admin_required
def security_logs():
    logs = get_db().execute(
        "SELECT l.*, u.username FROM security_logs l LEFT JOIN users u ON u.id = l.user_id ORDER BY l.id DESC LIMIT 100"
    ).fetchall()
    return render_template("security_logs.html", logs=logs)


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", title="Access denied", message="You do not have permission to open this page."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", title="Page not found", message="That page or record does not exist."), 404


if __name__ == "__main__":
    app.run(debug=False)

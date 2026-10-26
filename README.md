# Secure Student Management System

A beginner Flask and SQLite project with admin, teacher, and student roles, password hashing, record ownership checks, parameterized SQL, CSRF protection, and security event logs.

## Set up (Windows PowerShell)

```powershell
cd secure-student-management
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app create-admin
python app.py
```

Open http://127.0.0.1:5001. The `create-admin` command asks for a username, email, and password; password input stays hidden. To stop the server, press Ctrl+C.

If PowerShell blocks the activation script, use `.venv\Scripts\python.exe` instead of `python` for the remaining commands; for the Flask commands use `.venv\Scripts\python.exe -m flask ...`.

## Demo

1. Register two different students and note their student IDs on their profile pages.
2. Log in as the first student and visit `/students/SECOND_STUDENT_ID`; it should show Access denied.
3. Visit `/admin` as that student; it should also show Access denied.
4. Log in as admin. Open Security logs to see both blocked requests.
5. Add, edit, and delete a test student on the admin dashboard.
6. Try a wrong password once. It should appear in Security logs too.

The database and the generated session secret are stored in `instance/`, which is excluded by `.gitignore` and from the downloadable starter ZIP. Keep them private. This project is intended for a local classroom demo. If deploying it, configure HTTPS, secure session cookies, and additional login rate limiting.

## Upgrade an existing installation

1. Stop the server with Ctrl+C.
2. Make a backup copy of `instance\students.db` somewhere safe.
3. Replace `app.py`, `schema.sql`, `README.md`, `static\style.css`, and all files in `templates\` with the updated files. Do not replace or delete your `instance\` folder.
4. In the active virtual environment, run `python -m flask --app app init-db` once. This adds the teacher and attendance tables and preserves your existing accounts and students.
5. Run `python app.py`, then refresh the website. There is no need to create another admin account.

## Teachers and attendance demo

1. Log in as admin. Open **Teachers** and create a teacher login. Enter the course exactly as it appears on students, such as `Computer Science`, and a subject such as `Web Technology`.
2. Log out, then log in with the teacher's email and password. Open **Mark attendance**, choose a date, and press **Present** or **Absent** beside each student. Marking the same student, teacher, and date again corrects that entry.
3. Log out and log in as a student. Open **My attendance** to see that student's dates, subjects, statuses, and percentage.
4. As admin, open **Attendance** to see the overview and individual reports. An unmarked date is excluded from the percentage.

Teacher access is restricted to students whose course exactly matches the teacher's assigned course. Students can only see their own attendance; admins can see all reports. A teacher with saved attendance cannot be deleted, preserving existing reports.

# Secure Login System with User Role Management

A production-style cybersecurity internship project built with Flask. It demonstrates secure authentication, authorization, and role-based access control (RBAC) while applying practical defensive controls against common threats.

## Features

- User registration with server-side validation.
- Secure password hashing via Werkzeug's modern password hashing API.
- Login with session-based authentication.
- Role-based access control (`Admin` and `User`).
- Admin dashboard to view all registered users.
- CAPTCHA challenge (math-based) on login and registration forms.
- Account lockout after repeated failed login attempts.
- SQL injection resistance through SQLAlchemy ORM usage.
- CSRF protection on all POST forms.
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).

## Tech Stack

- **Backend:** Flask, Flask-Login, Flask-SQLAlchemy, Flask-WTF
- **Database:** SQLite (default), easily replaceable with MySQL/PostgreSQL
- **Frontend:** HTML + CSS (Jinja templates)
- **Testing:** Pytest (end-to-end style route tests)

## Project Structure

```bash
.
├── app.py
├── requirements.txt
├── static/
│   └── styles.css
├── templates/
│   ├── admin.html
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   └── register.html
└── tests/
    └── test_app.py
```

## Installation

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd Secure-Login-System-with-User-Role-Management
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # .venv\Scripts\activate   # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. (Recommended) Set environment variables:
   ```bash
   export SECRET_KEY="change-this-to-a-long-random-secret"
   export FLASK_ENV="production"  # enables secure session cookie flag
   ```

## How to Run

```bash
python app.py
```

Open: `http://127.0.0.1:5000`

## How to Use

1. Register a user account from `/register`.
2. Choose role:
   - `User` → standard dashboard access.
   - `Admin` → dashboard + admin panel access (`/admin`).
3. Login at `/login`.
4. For failed login attempts, lockout will trigger after 5 invalid tries.

## Security Controls Implemented

- **Input Validation:** Strict checks for username, email format, password strength, and role whitelist.
- **Password Security:** Passwords are hashed and never stored in plain text.
- **Authentication Security:** Session cookies with `HttpOnly` and `SameSite` options.
- **Authorization Security:** Decorator-based RBAC for admin-only endpoints.
- **Brute-force mitigation:** CAPTCHA + account lockout window.
- **CSRF Defense:** All state-changing forms protected by CSRF token.
- **Secure Headers:** CSP + clickjacking and MIME sniffing protections.

## Testing

Run all tests:

```bash
pytest -q
```

Covered test scenarios:
- Registration and login success flow.
- Admin page access restriction for non-admin users.
- Account lockout after repeated failed login attempts and unlock behavior.

## Challenges & Solutions

- **Challenge:** Preventing brute-force attacks on login.
  - **Solution:** Added CAPTCHA and account lockout with timed reset.
- **Challenge:** Avoiding privilege escalation.
  - **Solution:** Added explicit role checks on protected routes.
- **Challenge:** Keeping code simple but secure for internship review.
  - **Solution:** Used proven Flask extensions + test coverage for key security flows.

## Future Improvements

- Add email verification and password reset workflow.
- Integrate advanced CAPTCHA provider (hCaptcha/reCAPTCHA).
- Add audit logging and SIEM-ready event export.
- Use PostgreSQL and Alembic migrations for production lifecycle.

## Screenshots

- Login page screenshot is captured during validation and attached in the PR/report artifact.
- For GitHub repository display, you can add images under `docs/screenshots/` and link them in this section.

## Submission Checklist (Internship)

- [x] Secure login and registration forms
- [x] Password hashing and secure storage
- [x] RBAC with Admin/User roles
- [x] Brute-force protections
- [x] Testing and debugging evidence
- [x] Professional README with setup + usage + features

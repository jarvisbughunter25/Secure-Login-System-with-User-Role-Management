import re
from datetime import datetime, timedelta, timezone

import pytest

from app import User, create_app, db


def parse_captcha(html: str) -> str:
    match = re.search(r"What is (\d+) \+ (\d+)\?", html)
    assert match
    return str(int(match.group(1)) + int(match.group(2)))


@pytest.fixture
def app():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
        }
    )
    with app.app_context():
        db.drop_all()
        db.create_all()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username, email, password, role="User"):
    page = client.get("/register")
    captcha = parse_captcha(page.get_data(as_text=True))
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "role": role,
            "captcha": captcha,
        },
        follow_redirects=True,
    )


def login(client, email, password):
    page = client.get("/login")
    captcha = parse_captcha(page.get_data(as_text=True))
    return client.post(
        "/login",
        data={"email": email, "password": password, "captcha": captcha},
        follow_redirects=True,
    )


def test_registration_and_login_flow(client):
    strong_password = "StrongPass#123"
    response = register(client, "alice", "alice@example.com", strong_password)
    assert b"Registration successful" in response.data

    response = login(client, "alice@example.com", strong_password)
    assert b"Welcome, alice" in response.data


def test_rbac_admin_only_page(client, app):
    register(client, "user1", "user1@example.com", "StrongPass#123", "User")
    login(client, "user1@example.com", "StrongPass#123")
    response = client.get("/admin", follow_redirects=True)
    assert b"Unauthorized access" in response.data

    client.post("/logout", data={}, follow_redirects=True)
    register(client, "admin1", "admin1@example.com", "StrongPass#123", "Admin")
    login(client, "admin1@example.com", "StrongPass#123")
    response = client.get("/admin")
    assert response.status_code == 200
    assert b"Admin Dashboard" in response.data


def test_account_lockout(client, app):
    register(client, "bob", "bob@example.com", "StrongPass#123")

    for _ in range(5):
        page = client.get("/login")
        captcha = parse_captcha(page.get_data(as_text=True))
        client.post(
            "/login",
            data={"email": "bob@example.com", "password": "WrongPass#123", "captcha": captcha},
            follow_redirects=True,
        )

    page = client.get("/login")
    captcha = parse_captcha(page.get_data(as_text=True))
    response = client.post(
        "/login",
        data={"email": "bob@example.com", "password": "StrongPass#123", "captcha": captcha},
        follow_redirects=True,
    )
    assert b"temporarily locked" in response.data

    with app.app_context():
        user = User.query.filter_by(email="bob@example.com").first()
        user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()

    response = login(client, "bob@example.com", "StrongPass#123")
    assert b"Welcome, bob" in response.data

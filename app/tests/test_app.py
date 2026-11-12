from datetime import date, timedelta

import pytest

import main

PASSWORD = "correct-horse-battery"
TOMORROW = (date.today() + timedelta(days=1)).isoformat()


@pytest.fixture
def client(tmp_path):
    main.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
        DB_PATH=str(tmp_path / "test.db"),
    )
    main.init_db()
    with main.app.test_client() as client:
        yield client


def register_and_login(client, username="alice"):
    client.post("/register", data={"username": username, "password": PASSWORD})
    return client.post(
        "/login", data={"username": username, "password": PASSWORD}, follow_redirects=True
    )


def book(client, room="Study Room A", day=TOMORROW, slot="Morning"):
    return client.post(
        "/bookings",
        data={"room": room, "booking_date": day, "slot": slot},
        follow_redirects=True,
    )


def test_bookings_require_login(client):
    response = client.get("/bookings")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_register_and_login(client):
    response = register_and_login(client)
    assert b"My bookings" in response.data


def test_short_password_rejected(client):
    response = client.post(
        "/register", data={"username": "bob", "password": "short"}, follow_redirects=True
    )
    assert b"at least 12 characters" in response.data


def test_wrong_password_gives_generic_error(client):
    register_and_login(client)
    client.post("/logout")
    response = client.post(
        "/login", data={"username": "alice", "password": "wrong-password-123"}
    )
    assert b"Invalid username or password" in response.data


def test_create_booking(client):
    register_and_login(client)
    response = book(client)
    assert b"Booking confirmed" in response.data
    assert b"Study Room A" in response.data


def test_double_booking_blocked(client):
    register_and_login(client)
    book(client)
    response = book(client)
    assert b"already booked" in response.data


def test_past_date_rejected(client):
    register_and_login(client)
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    response = book(client, day=yesterday)
    assert b"today or a future date" in response.data


def test_invalid_room_rejected(client):
    register_and_login(client)
    response = book(client, room="Admin Office")
    assert b"valid room" in response.data


def test_security_headers_present(client):
    response = client.get("/login")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_csrf_enforced(client):
    main.app.config["WTF_CSRF_ENABLED"] = True
    response = client.post("/register", data={"username": "eve", "password": PASSWORD})
    assert response.status_code == 400


def test_search_filters_own_bookings(client):
    register_and_login(client)
    book(client, room="Study Room A")
    book(client, room="Meeting Room")
    response = client.get("/bookings/search?room=Meeting")
    assert b"Meeting Room" in response.data
    assert b"<td>Study Room A</td>" not in response.data


def test_search_treats_sql_as_text(client):
    register_and_login(client)
    book(client)
    response = client.get("/bookings/search?room=' OR '1'='1")
    assert response.status_code == 200
    assert b"<td>Study Room A</td>" not in response.data

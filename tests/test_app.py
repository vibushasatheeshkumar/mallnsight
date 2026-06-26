import io
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize("route", ["/", "/about", "/features", "/upload", "/contact"])
def test_static_pages_load(client, route):
    response = client.get(route)
    assert response.status_code == 200


def test_analyze_requires_a_file(client):
    response = client.post("/analyze", data={})
    assert response.status_code == 400


def test_analyze_rejects_get(client):
    response = client.get("/analyze")
    assert response.status_code == 405


def test_analyze_rejects_disallowed_extension(client):
    data = {
        "file": (io.BytesIO(b"hello world"), "notes.txt")
    }
    response = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert response.status_code == 400


def test_analyze_accepts_pe_file(client):
    pe_path = os.path.join(os.path.dirname(sys.executable), "python.exe")

    if not os.path.exists(pe_path):
        pytest.skip("No PE binary available to test with on this platform")

    with open(pe_path, "rb") as f:
        data = {
            "file": (io.BytesIO(f.read()), "sample.exe")
        }
        response = client.post("/analyze", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    assert b"Risk Score" in response.data

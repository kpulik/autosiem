import os
import pytest

@pytest.fixture(autouse=True)
def enable_insecure_auth_for_tests(monkeypatch):
    """Ensure unauthenticated tests continue to pass in dev/test mode."""
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")

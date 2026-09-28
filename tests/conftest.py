import os
import socket
import threading

import pytest

@pytest.fixture(autouse=True)
def enable_insecure_auth_for_tests(monkeypatch):
    """Ensure unauthenticated tests continue to pass in dev/test mode."""
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")


@pytest.fixture
def silent_server():
    """Accepts connections and never answers, like a wedged cluster."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(listener.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    stop.set()
    thread.join()
    for conn in held:
        conn.close()
    listener.close()

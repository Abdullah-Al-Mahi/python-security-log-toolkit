"""Optional real Streamlit smoke test (runs when the [web] extra is installed).

No mocking: the test checks that Streamlit can run the initial demo page.
"""
from pathlib import Path
import pytest

streamlit = pytest.importorskip("streamlit", reason="Optional web dependencies not installed; install .[dev,web] for UI smoke test")
from streamlit.testing.v1 import AppTest


def test_initial_demo_page_renders_without_exceptions():
    app = Path(__file__).resolve().parents[1] / "dashboard/app.py"
    rendered = AppTest.from_file(str(app), default_timeout=45).run()
    assert not rendered.exception

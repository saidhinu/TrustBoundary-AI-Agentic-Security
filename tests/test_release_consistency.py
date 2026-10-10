from pathlib import Path
from fastapi.testclient import TestClient
from trustboundary import __version__
from trustboundary.api import app


def test_version_single_source_of_truth_and_readme_heading():
    root=Path(__file__).resolve().parents[1]
    readme=(root/'README.md').read_text(encoding='utf-8')
    assert ('v'+__version__) in readme.splitlines()[0]
    assert TestClient(app).get('/health').json()['version']==__version__
    page=TestClient(app).get('/').text
    assert 'id="appVersion"' in page
    assert "health.version" in (root/'web/app.js').read_text(encoding='utf-8')

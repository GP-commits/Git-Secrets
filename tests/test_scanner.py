import os
import sys
import json
import pytest
from unittest.mock import patch
from io import StringIO
from pathlib import Path

# Adjust path so we can import scanner
sys.path.insert(0, str(Path(__file__).parent.parent))
import scanner

def test_redact_short_string():
    # keep = 6 by default
    assert scanner._redact("short") == "short"
    assert scanner._redact("123456") == "123456"

def test_redact_long_string():
    # keep = 6 by default
    full_secret = "1234567890abcdef"
    redacted = scanner._redact(full_secret)
    assert redacted == "123456**********"

def test_finding_dataclass_holds_both_snippets():
    f = scanner.Finding(
        repo="test",
        file="file.txt",
        line_number=1,
        secret_type="dummy",
        snippet="redacted_***",
        source="file",
        raw_snippet="redacted_raw"
    )
    assert f.snippet == "redacted_***"
    assert f.raw_snippet == "redacted_raw"

def test_export_json_excludes_raw_snippet(tmp_path):
    f = scanner.Finding(
        repo="repo_test",
        file="file.txt",
        line_number=1,
        secret_type="AWS Key",
        snippet="AKIA**********",
        source="file",
        raw_snippet="AKIA123456789X"
    )
    res = scanner.ScanResult(username="tester", findings=[f])
    out_file = tmp_path / "out.json"
    
    scanner.export_json(res, str(out_file))
    
    data = json.loads(out_file.read_text("utf-8"))
    assert "raw_snippet" not in data["findings"][0]
    assert data["findings"][0]["snippet"] == "AKIA**********"

@patch("sys.argv", ["scanner.py", "orgtest", "--unsafe-show-secrets", "--yes"])
@patch("scanner.fetch_repos", return_value=[])  # Stop it from hitting API
@patch("scanner._log")
def test_main_shows_secrets_with_yes(mock_log, mock_fetch):
    # Ensure CI is not set for this test
    with patch.dict(os.environ, clear=True):
        try:
            scanner.main()
        except SystemExit:
            pass
        assert scanner._SHOW_SECRETS is True

@patch("sys.argv", ["scanner.py", "orgtest", "--unsafe-show-secrets", "--yes"])
@patch("scanner.fetch_repos", return_value=[])
@patch("scanner._log")
def test_main_ci_blocks_show_secrets(mock_log, mock_fetch):
    # If CI=true, it should revert to redaction despite --yes
    with patch.dict(os.environ, {"CI": "true"}):
        try:
            scanner.main()
        except SystemExit:
            pass
        assert scanner._SHOW_SECRETS is False

@patch("sys.argv", ["scanner.py", "orgtest", "--unsafe-show-secrets"])
@patch("scanner.fetch_repos", return_value=[])
@patch("sys.stdout")
@patch("scanner._log")
def test_main_non_tty_blocks_show_secrets(mock_log, mock_stdout, mock_fetch):
    mock_stdout.isatty.return_value = False
    with patch.dict(os.environ, clear=True):
        try:
            scanner.main()
        except SystemExit:
            pass
        # _SHOW_SECRETS should be False because it's not a TTY and no --yes was provided
        assert scanner._SHOW_SECRETS is False


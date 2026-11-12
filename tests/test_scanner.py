import subprocess

import httpx
import pytest
from pydantic import ValidationError

from src import scanner
from src.scanner import ScannerError, ScanTarget, audit_headers, run_nmap

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="3000">
    <state state="open"/>
    <service name="http" product="Node.js Express framework" version="4.0"/>
  </port>
</ports></host></nmaprun>"""


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:3000", "https://example.com", "http://juice-shop.local:8080"],
)
def test_target_accepts_valid_urls(url: str) -> None:
    assert ScanTarget(url=url)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1",
        "http://-oN/tmp/x",
        "http://--script=evil",
        "http://a;b",
        "not a url",
    ],
)
def test_target_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        ScanTarget(url=url)


def test_target_port_defaults() -> None:
    assert ScanTarget(url="http://127.0.0.1:3000").port == 3000
    assert ScanTarget(url="http://127.0.0.1").port == 80
    assert ScanTarget(url="https://127.0.0.1").port == 443


def test_run_nmap_parses_xml_and_uses_safe_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    ports = run_nmap(ScanTarget(url="http://127.0.0.1:3000"))

    cmd, kwargs = calls[0]
    assert cmd == ["nmap", "-sV", "-p", "3000", "-oX", "-", "127.0.0.1"]
    assert kwargs["shell"] is False
    assert ports[0].port == 3000
    assert ports[0].state == "open"
    assert ports[0].product == "Node.js Express framework"


def test_run_nmap_raises_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda cmd, **_: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom"),
    )
    with pytest.raises(ScannerError):
        run_nmap(ScanTarget(url="http://127.0.0.1:3000"))


def test_audit_headers_detects_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url: str, **_: object) -> httpx.Response:
        return httpx.Response(200, headers={"x-frame-options": "SAMEORIGIN"})

    monkeypatch.setattr(scanner.httpx, "get", fake_get)

    audit = audit_headers(ScanTarget(url="http://127.0.0.1:3000"))

    assert audit.present == {"X-Frame-Options": "SAMEORIGIN"}
    assert "Content-Security-Policy" in audit.missing
    assert "X-Frame-Options" not in audit.missing

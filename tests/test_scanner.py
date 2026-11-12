import socket
import subprocess
from collections.abc import Iterator

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


@pytest.fixture(autouse=True)
def allowed_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fija la lista blanca para que los tests no dependan del entorno.
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "127.0.0.1")


def fake_dns(monkeypatch: pytest.MonkeyPatch, ip: str) -> None:
    """Simula que cualquier hostname resuelve a `ip` (sin tocar la red)."""

    def fake_getaddrinfo(host: str, port: int, **_: object) -> list:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(scanner.socket, "getaddrinfo", fake_getaddrinfo)


def mock_transport(
    response: httpx.Response, requests: list[httpx.Request]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return response

    return httpx.MockTransport(handler)


# --- Validación de entrada ---------------------------------------------------


def test_target_accepts_allowed_ip() -> None:
    assert ScanTarget(url="http://127.0.0.1:3000").ip == "127.0.0.1"


@pytest.mark.parametrize("url", ["https://example.com", "http://juice-shop.local:8080"])
def test_target_accepts_hostname_resolving_to_allowed_ip(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    fake_dns(monkeypatch, "127.0.0.1")
    assert ScanTarget(url=url).ip == "127.0.0.1"


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


@pytest.mark.parametrize(
    "url", ["http://admin:S3cret@127.0.0.1:3000", "http://admin@127.0.0.1:3000"]
)
def test_target_rejects_credentials(url: str) -> None:
    # M1: las credenciales no deben llegar al reporte ni a la petición.
    with pytest.raises(ValidationError, match="credenciales"):
        ScanTarget(url=url)


def test_target_rejects_port_zero() -> None:
    # I1: antes el puerto 0 hacía que nmap escaneara el 80.
    with pytest.raises(ValidationError, match="puerto 0"):
        ScanTarget(url="http://127.0.0.1:0")


def test_target_port_defaults() -> None:
    assert ScanTarget(url="http://127.0.0.1:3000").port == 3000
    assert ScanTarget(url="http://127.0.0.1").port == 80
    assert ScanTarget(url="https://127.0.0.1").port == 443


# --- Lista blanca SCAN_ALLOWED_HOSTS (M2 / B3) ------------------------------------


def test_target_rejects_ip_outside_allowlist() -> None:
    with pytest.raises(ValidationError, match="SCAN_ALLOWED_HOSTS"):
        ScanTarget(url="http://8.8.8.8")


def test_target_rejects_hostname_resolving_outside_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # B3: se autoriza la IP resuelta, no el nombre.
    fake_dns(monkeypatch, "10.0.0.5")
    with pytest.raises(ValidationError, match="SCAN_ALLOWED_HOSTS"):
        ScanTarget(url="http://juice-shop.local:3000")


def test_target_rejects_everything_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "")
    with pytest.raises(ValidationError, match="SCAN_ALLOWED_HOSTS"):
        ScanTarget(url="http://127.0.0.1:3000")


def test_allowlist_accepts_cidr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "127.0.0.1, 10.0.0.0/24")
    assert ScanTarget(url="http://10.0.0.5:3000").ip == "10.0.0.5"


def test_allowlist_defaults_to_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCAN_ALLOWED_HOSTS")
    assert ScanTarget(url="http://127.0.0.1:3000")
    with pytest.raises(ValidationError):
        ScanTarget(url="http://10.0.0.5:3000")


# --- nmap ----------------------------------------------------------------------


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


def test_run_nmap_scans_resolved_ip_not_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # B3: nmap recibe la IP autorizada, no vuelve a resolver el nombre.
    fake_dns(monkeypatch, "127.0.0.1")
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    run_nmap(ScanTarget(url="http://juice-shop.local:3000"))

    assert calls[0][-1] == "127.0.0.1"


def test_run_nmap_raises_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda cmd, **_: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom"),
    )
    with pytest.raises(ScannerError):
        run_nmap(ScanTarget(url="http://127.0.0.1:3000"))


# --- Cabeceras HTTP ----------------------------------------------------------------


def test_audit_headers_detects_missing() -> None:
    requests: list[httpx.Request] = []
    transport = mock_transport(
        httpx.Response(200, headers={"x-frame-options": "SAMEORIGIN"}), requests
    )

    audit = audit_headers(ScanTarget(url="http://127.0.0.1:3000"), transport=transport)

    assert audit.status_code == 200
    assert audit.present == {"X-Frame-Options": "SAMEORIGIN"}
    assert "Content-Security-Policy" in audit.missing
    assert "X-Frame-Options" not in audit.missing
    assert audit.redirect_location is None


def test_audit_headers_does_not_follow_redirect() -> None:
    # M3: se reporta la redirección pero no se sigue hacia otro host.
    requests: list[httpx.Request] = []
    transport = mock_transport(
        httpx.Response(302, headers={"Location": "https://evil.example/"}), requests
    )

    audit = audit_headers(ScanTarget(url="http://127.0.0.1:3000"), transport=transport)

    assert len(requests) == 1
    assert audit.status_code == 302
    assert audit.redirect_location == "https://evil.example/"


def test_audit_headers_connects_to_resolved_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # B3: la petición va a la IP autorizada; Host y SNI conservan el nombre.
    fake_dns(monkeypatch, "127.0.0.1")
    requests: list[httpx.Request] = []
    transport = mock_transport(httpx.Response(200), requests)

    audit_headers(ScanTarget(url="https://juice-shop.local:3000/"), transport=transport)

    request = requests[0]
    assert request.url.host == "127.0.0.1"
    assert request.headers["Host"] == "juice-shop.local:3000"
    assert request.extensions["sni_hostname"] == "juice-shop.local"


class _UnreadableStream(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        raise AssertionError("no se debe leer el cuerpo de la respuesta")


def test_audit_headers_does_not_read_body() -> None:
    # B1: un cuerpo enorme no debe cargarse en memoria.
    requests: list[httpx.Request] = []
    transport = mock_transport(
        httpx.Response(200, stream=_UnreadableStream()), requests
    )

    audit = audit_headers(ScanTarget(url="http://127.0.0.1:3000"), transport=transport)

    assert audit.status_code == 200

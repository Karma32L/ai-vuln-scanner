"""Módulo de reconocimiento inicial: escaneo de puertos/versiones y cabeceras HTTP."""

import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

import httpx
from pydantic import BaseModel, Field, HttpUrl, field_validator

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
)

# Hostname RFC 1123: etiquetas alfanuméricas, guiones solo en el interior.
# Impide que el host empiece por "-" y sea interpretado por nmap como una opción.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


class ScannerError(Exception):
    """Error al ejecutar o interpretar el escaneo de nmap."""


class ScanTarget(BaseModel):
    """Objetivo validado. Es la única vía para que datos externos lleguen a nmap/httpx."""

    url: HttpUrl

    @field_validator("url")
    @classmethod
    def validate_host(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme not in ("http", "https"):
            raise ValueError("solo se permiten URLs http/https")
        host = (value.host or "").strip("[]")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(host):
                raise ValueError(f"host no válido: {host!r}") from None
        return value

    @property
    def host(self) -> str:
        # Pydantic devuelve IPv6 entre corchetes; nmap los necesita sin ellos.
        return (self.url.host or "").strip("[]")

    @property
    def port(self) -> int:
        # HttpUrl ya resuelve el puerto por defecto (80/443) si no se indica.
        return self.url.port or (443 if self.url.scheme == "https" else 80)

    @property
    def is_ipv6(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).version == 6
        except ValueError:
            return False


class PortResult(BaseModel):
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


class HeaderAudit(BaseModel):
    status_code: int
    present: dict[str, str]
    missing: list[str]


class ScanReport(BaseModel):
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ports: list[PortResult] = Field(default_factory=list)
    headers: HeaderAudit | None = None
    errors: list[str] = Field(default_factory=list)


def _parse_nmap_xml(xml_output: str) -> list[PortResult]:
    # El XML lo genera nmap localmente; si se parseara XML externo usar defusedxml.
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise ScannerError(f"salida XML de nmap no válida: {exc}") from exc

    results: list[PortResult] = []
    for port in root.iter("port"):
        state = port.find("state")
        service = port.find("service")
        results.append(
            PortResult(
                port=int(port.get("portid", "0")),
                protocol=port.get("protocol", "tcp"),
                state=state.get("state", "unknown") if state is not None else "unknown",
                service=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
            )
        )
    return results


def run_nmap(target: ScanTarget, timeout: int = 120) -> list[PortResult]:
    """Ejecuta `nmap -sV` sobre el puerto del objetivo y devuelve los puertos detectados."""
    if shutil.which("nmap") is None:
        raise ScannerError("nmap no está instalado o no está en el PATH")

    cmd = ["nmap", "-sV", "-p", str(target.port), "-oX", "-"]
    if target.is_ipv6:
        cmd.append("-6")
    cmd.append(target.host)

    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"nmap superó el tiempo límite de {timeout}s") from exc

    if proc.returncode != 0:
        raise ScannerError(
            f"nmap terminó con código {proc.returncode}: {proc.stderr.strip()}"
        )
    return _parse_nmap_xml(proc.stdout)


def audit_headers(target: ScanTarget, timeout: float = 10.0) -> HeaderAudit:
    """Hace un GET y reporta qué cabeceras de seguridad están presentes o faltan."""
    response = httpx.get(str(target.url), timeout=timeout, follow_redirects=True)
    # httpx.Headers es case-insensitive, así que la comparación es directa.
    present = {
        name: response.headers[name]
        for name in SECURITY_HEADERS
        if name in response.headers
    }
    missing = [name for name in SECURITY_HEADERS if name not in present]
    return HeaderAudit(
        status_code=response.status_code, present=present, missing=missing
    )


def scan(target: ScanTarget) -> ScanReport:
    """Orquesta ambos escaneos; un fallo parcial se registra en `errors` sin abortar."""
    report = ScanReport(target=str(target.url))

    try:
        report.ports = run_nmap(target)
    except ScannerError as exc:
        report.errors.append(f"nmap: {exc}")

    try:
        report.headers = audit_headers(target)
    except httpx.HTTPError as exc:
        report.errors.append(f"http: {exc}")

    return report

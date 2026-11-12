"""Módulo de reconocimiento inicial: escaneo de puertos/versiones y cabeceras HTTP."""

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Self

import httpx
from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    PrivateAttr,
    field_validator,
    model_validator,
)

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
)

DEFAULT_ALLOWED_HOSTS = "127.0.0.1"

# Hostname RFC 1123: etiquetas alfanuméricas, guiones solo en el interior.
# Impide que el host empiece por "-" y sea interpretado por nmap como una opción.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


class ScannerError(Exception):
    """Error al ejecutar o interpretar el escaneo de nmap."""


def _allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Lee SCAN_ALLOWED_HOSTS (IPs o CIDR separados por comas). Vacío = nada permitido."""
    raw = os.getenv("SCAN_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)
    return [
        ipaddress.ip_network(entry.strip(), strict=False)
        for entry in raw.split(",")
        if entry.strip()
    ]


def _resolve(host: str, port: int) -> str:
    """Resuelve el host una única vez; nmap y httpx usarán esta misma IP."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"no se pudo resolver {host!r}") from exc
    return str(infos[0][4][0])


class ScanTarget(BaseModel):
    """Objetivo validado. Es la única vía para que datos externos lleguen a nmap/httpx."""

    url: HttpUrl
    _ip: str = PrivateAttr(default="")

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme not in ("http", "https"):
            raise ValueError("solo se permiten URLs http/https")
        # Las credenciales acabarían en el reporte JSON y en la petición HTTP.
        if value.username or value.password:
            raise ValueError("la URL no debe contener credenciales")
        if value.port == 0:
            raise ValueError("el puerto 0 no es válido")
        host = (value.host or "").strip("[]")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(host):
                raise ValueError(f"host no válido: {host!r}") from None
        return value

    @model_validator(mode="after")
    def resolve_and_authorize(self) -> Self:
        # Se autoriza la IP resuelta, no el nombre: evita saltarse la lista vía DNS.
        ip = _resolve(self.host, self.port)
        ip_obj = ipaddress.ip_address(ip)
        if not any(ip_obj in net for net in _allowed_networks()):
            raise ValueError(f"{ip} no está en SCAN_ALLOWED_HOSTS")
        self._ip = ip
        return self

    @property
    def host(self) -> str:
        # Pydantic devuelve IPv6 entre corchetes; nmap los necesita sin ellos.
        return (self.url.host or "").strip("[]")

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def port(self) -> int:
        if self.url.port is not None:
            return self.url.port
        return 443 if self.url.scheme == "https" else 80

    @property
    def is_ipv6(self) -> bool:
        return ipaddress.ip_address(self.ip).version == 6


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
    redirect_location: str | None = None


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
    cmd.append(target.ip)

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


def audit_headers(
    target: ScanTarget,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> HeaderAudit:
    """Hace un GET y reporta qué cabeceras de seguridad están presentes o faltan."""
    url = httpx.URL(str(target.url))
    # Conecta a la IP ya autorizada; Host y SNI conservan el nombre original.
    request_url = url.copy_with(host=target.ip)
    # Sin seguir redirecciones: no se sale del objetivo autorizado.
    # stream() evita descargar el cuerpo: solo interesan las cabeceras.
    with (
        httpx.Client(
            timeout=timeout, follow_redirects=False, transport=transport
        ) as client,
        client.stream(
            "GET",
            request_url,
            headers={"Host": url.netloc.decode()},
            extensions={"sni_hostname": target.host},
        ) as response,
    ):
        # httpx.Headers es case-insensitive, así que la comparación es directa.
        present = {
            name: response.headers[name]
            for name in SECURITY_HEADERS
            if name in response.headers
        }
        redirect = response.headers.get("Location") if response.is_redirect else None
        status_code = response.status_code

    missing = [name for name in SECURITY_HEADERS if name not in present]
    return HeaderAudit(
        status_code=status_code,
        present=present,
        missing=missing,
        redirect_location=redirect,
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

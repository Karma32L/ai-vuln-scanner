import pytest
from typer.testing import CliRunner

from src import main as cli
from src.analyzer import AnalyzerError
from src.scanner import ScanReport

runner = CliRunner()


class FakeClient:
    def __init__(self, reply: str = "## Resumen Ejecutivo\nOK") -> None:
        self.reply = reply

    def complete(self, system: str, user: str) -> str:
        return self.reply


class FailingClient:
    def complete(self, system: str, user: str) -> str:
        raise AnalyzerError("sin conexión")


@pytest.fixture(autouse=True)
def fake_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "127.0.0.1")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setattr(cli, "scan", lambda target: ScanReport(target=str(target.url)))


def test_without_analyze_only_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "build_client", lambda _: pytest.fail("no debe llamarse"))
    result = runner.invoke(cli.app, ["http://127.0.0.1:3000"])
    assert result.exit_code == 0
    assert '"target"' in result.output


def test_analyze_prints_markdown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "build_client", lambda _: FakeClient())
    result = runner.invoke(cli.app, ["http://127.0.0.1:3000", "--analyze"])
    assert result.exit_code == 0
    assert '"target"' in result.output
    assert "## Resumen Ejecutivo" in result.output


def test_analyze_failure_keeps_json_and_exits_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "build_client", lambda _: FailingClient())
    result = runner.invoke(cli.app, ["http://127.0.0.1:3000", "--analyze"])
    assert result.exit_code == 1
    assert '"target"' in result.output
    assert "Análisis IA fallido" in result.output


def test_invalid_llm_config_does_not_leak_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "otro")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secreto")
    result = runner.invoke(cli.app, ["http://127.0.0.1:3000", "--analyze"])
    assert result.exit_code == 1
    assert "Configuración LLM no válida" in result.output
    assert "sk-secreto" not in result.output

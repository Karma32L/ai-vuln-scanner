"""CLI del escáner: recibe una URL y emite el resultado en JSON (y opcionalmente análisis IA)."""

import typer
from pydantic import ValidationError

from src.analyzer import AnalyzerError, LLMSettings, analyze, build_client
from src.scanner import ScanReport, ScanTarget, scan

app = typer.Typer(
    add_completion=False, help="Reconocimiento inicial de un objetivo web."
)


def _run_analysis(report: ScanReport) -> bool:
    """Imprime el reporte Markdown. Devuelve False si el análisis falló."""
    try:
        client = build_client(LLMSettings.from_env())
        typer.echo(analyze(report, client))
    except ValidationError as exc:
        # Solo el mensaje: str(exc) podría incluir el valor de ANTHROPIC_API_KEY.
        typer.echo(f"Configuración LLM no válida: {exc.errors()[0]['msg']}", err=True)
        return False
    except AnalyzerError as exc:
        typer.echo(f"Análisis IA fallido: {exc}", err=True)
        return False
    return True


@app.command()
def main(
    url: str = typer.Argument(
        "http://127.0.0.1:3000", help="URL del objetivo autorizado."
    ),
    run_ai: bool = typer.Option(
        False, "--analyze", help="Genera un reporte Markdown con el LLM configurado."
    ),
) -> None:
    try:
        target = ScanTarget(url=url)
    except ValidationError as exc:
        typer.echo(f"URL no válida: {exc.errors()[0]['msg']}", err=True)
        raise typer.Exit(code=2) from None

    report = scan(target)
    typer.echo(report.model_dump_json(indent=2))

    ok = not report.errors
    if run_ai:
        typer.echo()
        ok = _run_analysis(report) and ok
    if not ok:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

"""CLI del escáner: recibe una URL y emite el resultado en JSON."""

import typer
from pydantic import ValidationError

from src.scanner import ScanTarget, scan

app = typer.Typer(
    add_completion=False, help="Reconocimiento inicial de un objetivo web."
)


@app.command()
def main(
    url: str = typer.Argument(
        "http://127.0.0.1:3000", help="URL del objetivo autorizado."
    ),
) -> None:
    try:
        target = ScanTarget(url=url)
    except ValidationError as exc:
        typer.echo(f"URL no válida: {exc.errors()[0]['msg']}", err=True)
        raise typer.Exit(code=2) from None

    report = scan(target)
    typer.echo(report.model_dump_json(indent=2))
    if report.errors:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

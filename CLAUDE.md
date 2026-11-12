# Contexto del Proyecto
Repositorio de Ciberseguridad e IA. Entorno: Ubuntu Linux, Python 3.11+, Docker.

# Comandos Clave
- Linter: `ruff check . --fix && ruff format .`
- Pruebas: `pytest`
- Laboratorio: `docker compose -f lab/docker-compose.yml up -d`

# Reglas de Seguridad (ESTRICTAS)
1. Cero secretos hardcodeados. Usa siempre `os.getenv()`.
2. Usa type hints y Pydantic para validar entradas externas.
3. Usa `subprocess.run(["cmd", "arg"], shell=False)` para evitar Command Injection.
4. Antes de modificar más de 3 archivos, presenta un plan y espera confirmación.

# Git
- Usa Conventional Commits (`feat:`, `fix:`, `sec:`, `docs:`).
- Nunca hagas push directo a `main`.

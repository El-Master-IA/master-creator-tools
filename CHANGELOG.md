# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semantico.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [Unreleased]

## [0.2.0] - 2026-11-12

### Added / Agregado

- Adaptadores `python`, `estatico` y `generico` (respaldo), con detección por tabla de confianza y `--type n8n|node|python|estatico|generico|auto` / `python`, `estatico` and `generico` (fallback) adapters, confidence-based detection and the new `--type` values (DET-001, PY-001…003, WEB-001…002, GEN-001).
- Licencias de dependencias Python vía lockfile y PyPI, sin consultar nunca índices privados / Python dependency licenses from lockfiles and PyPI, never querying private indexes (LIC-005, LIC-006).
- `mct sanitize --decisiones <archivo>` y `--auto-fixtures` (con confirmación por sha256) para revisar sin TTY / decision files and auto-fixtures (sha256-confirmed) to review without a TTY (SAN-012…015).
- `hallazgosAbiertos` en `scan`/`sanitize --json` y `pendientes` en `licenses --json` / new JSON fields for tools (SAN-013).
- CI y README generados según el adaptador; verify omitido con aviso para el genérico; resumen antes de publicar / per-adapter CI and README, skipped verify warning for generic, pre-publish summary (PKG-006, PKG-007, VER-007, PUB-013).
- Plugin de Claude Code `/liberar` en `plugin/` / Claude Code plugin `/liberar` (PLG-001…005).

### Changed / Cambiado

- Ids de hallazgos con HMAC por workspace (`.mct/clave`); un workspace de 0.1.x pide `mct init --force` / finding ids are HMAC-keyed per workspace; 0.1.x workspaces need `mct init --force` (SCAN-015).
- Todo secreto y todo hallazgo de gitleaks es `critico` / every secret and gitleaks finding is `critico` (SCAN-014).
- Contrato `Adapter`/`VerifySpec`: `verifyCommand` puede devolver `null`, `start` admite secuencias con `avisoSiFalla`, healthcheck `http` con `ruta`, `aceptar`, `cuerpoContiene` y `rutasExtra` / adapter contract changes (minor bump in 0.x).

## [0.1.2] - 2026-11-12

### Fixed / Corregido

- `doctor`: con `verify.remoto` que responde, Docker local ausente o apagado es aviso y no el siguiente paso / with a reachable `verify.remoto`, a missing or stopped local Docker is a warning, not the next step (CLI-007).

## [0.1.1] - 2026-11-11

### Changed / Cambiado

- `init` usa el `mct.config.json` del origen si el destino no tiene uno y lo copia al destino / `init` uses the source `mct.config.json` when the destination has none and copies it there (CFG-002).
- `sanitize` deja `scan` en `ok` al cerrar todos los hallazgos / `sanitize` sets `scan` to `ok` once no finding is open (SAN-010).
- `sanitize` ofrece aplicar una decisión con motivo a los hallazgos de la misma regla y carpeta (pide confirmar) / `sanitize` offers to apply a reasoned decision to findings of the same rule and folder (asks first) (SAN-011).

### Fixed / Corregido

- `publish` reintenta el release y los topics ante un 404 pasajero de GitHub / `publish` retries the release and topics on a transient GitHub 404 (PUB-012).
- `init` muestra la confianza del adaptador con dos decimales / `init` shows the adapter confidence with two decimals.

## [0.1.0] - 2026-11-11

### Added / Agregado

- Pipeline de 7 etapas / 7-stage pipeline: `init`, `scan`, `sanitize`, `licenses`, `package`, `verify`, `publish`.
- Comandos / Commands: `mct run`, `mct doctor`, `mct clean`.
- Adaptadores para n8n y Node / n8n and Node adapters.
- Documentacion ES/EN y `.env.example` / ES/EN docs and `.env.example`.

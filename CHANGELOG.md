# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semantico.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [Unreleased]

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

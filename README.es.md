# master-creator-tools

> Read this in English: [README.md](README.md)

## Requisitos

- Node >= 22

## Instalación

```sh
pnpm install --frozen-lockfile && pnpm run build
```

## Uso

```sh
pnpm start
```

## Variables de entorno

- `SystemRoot` (obligatoria): Obligatoria.
- `PATH` (obligatoria): Obligatoria.
- `GITLEAKS_CONFIG` (obligatoria): Obligatoria.
- `GITLEAKS_CONFIG_TOML` (obligatoria): Obligatoria.
- `HOME` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `USERPROFILE` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `MCT_BIN` (obligatoria): Obligatoria.
- `MCT_LOG` (obligatoria): Obligatoria.
- `MCT_ESC` (obligatoria): Obligatoria.
- `GITHUB_TOKEN` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `GH_TOKEN` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `NO_COLOR` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `TERM` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `LANG` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `LC_ALL` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `GIT_ASKPASS` (opcional): Opcional (tiene valor por defecto o es de ejemplo).
- `DOCKER_HOST` (opcional): Opcional (tiene valor por defecto o es de ejemplo).

Copia `.env.example` a `.env` y completa los valores. Nunca subas `.env` al repositorio.

## Documentación

- [Instalación](docs/es/instalacion.md)
- [Uso](docs/es/uso.md)
- [Qué hacer ante un incidente](docs/es/incidentes.md)

## Contribuir y seguridad

Lee [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) y [SECURITY.md](SECURITY.md).

## Licencia

MIT, copyright 2026 Alexander Cast. Consulta [LICENSE](LICENSE).

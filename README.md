# master-creator-tools

> Lee esto en español: [README.es.md](README.es.md)

## Requirements

- Node >= 22

## Installation

```sh
pnpm install --frozen-lockfile && pnpm run build
```

## Usage

```sh
pnpm start
```

## Environment variables

- `SystemRoot` (required): Obligatoria.
- `PATH` (required): Obligatoria.
- `GITLEAKS_CONFIG` (required): Obligatoria.
- `GITLEAKS_CONFIG_TOML` (required): Obligatoria.
- `HOME` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `USERPROFILE` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `MCT_BIN` (required): Obligatoria.
- `MCT_LOG` (required): Obligatoria.
- `MCT_ESC` (required): Obligatoria.
- `GITHUB_TOKEN` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `GH_TOKEN` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `NO_COLOR` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `TERM` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `LANG` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `LC_ALL` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `GIT_ASKPASS` (optional): Opcional (tiene valor por defecto o es de ejemplo).
- `DOCKER_HOST` (optional): Opcional (tiene valor por defecto o es de ejemplo).

Copy `.env.example` to `.env` and fill in the values. Never commit `.env` to the repository.

## Documentation

- [Installation](docs/en/install.md)
- [Usage](docs/en/usage.md)
- [What to do after an incident](docs/en/incidents.md)

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).

## License

MIT, copyright 2026 Alexander Cast. See [LICENSE](LICENSE).

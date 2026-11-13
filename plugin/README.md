# Plugin `/liberar` para Claude Code

Convierte un repo en una herramienta pública con un solo comando: `/liberar` lee el proyecto, te muestra el plan completo (repo, licencia, README, verificación, publicación y, si tienes la skill de El Laboratorio, portada y página) y con un solo sí lo hace todo. Solo se detiene si encuentra un secreto o dato real, una licencia por revisar o un error de `mct`.

## Contenido

| Archivo | Para qué |
|---|---|
| `.claude-plugin/plugin.json` | Manifiesto (`liberar`, 0.3.0) |
| `commands/liberar.md` | Guion que sigue Claude (pregunta, muestra, orquesta) |
| `scripts/liberar.mjs` | Lógica determinista, Node sin dependencias, JSON por subcomando |
| `test/liberar.test.ts` | Pruebas (`pnpm vitest run plugin/test`) con un `mct` simulado |

## Instalar

Desde la raíz del repo: `claude --plugin-dir ./plugin`, o agrega la carpeta `plugin/` a un marketplace propio.

## `mct` que usa

`MCT_BIN` si está definida; si no, `node_modules/.bin/mct` del origen; si no, `npx -p master-creator-tools@<versión del plugin> mct`.

## Destino fijo

Todo se hace en `<home>/.mct/liberar/<carpeta del origen>` (`HOME` o `USERPROFILE`). En el origen solo se escribe `mct.config.json`, y solo con el sí del plan.

## Subcomandos de `liberar.mjs`

`destino`, `doctor`, `proponer-config`, `etapas` (`plan`, `ejecutar`, `interpretar`), `revision` (`fixtures`, `aplicar-fixtures`, `hallazgos`, `aplicar-decisiones`), `escribir-decisiones`, `override-licencias`, `readme`, `resumen`, `publicar`. Salida 0 = sigue, 2 = uso inválido, 3 = el flujo se detiene.

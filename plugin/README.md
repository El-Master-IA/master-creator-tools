# Plugin `/liberar` para Claude Code

Libera un repo con `mct` desde Claude Code: `/liberar` corre el diagnóstico, propone la configuración, ejecuta las puertas (`init`, `scan`, `sanitize`, `licenses`, `package`, `verify`) y pregunta cada decisión de seguridad. **Nunca publica**: el último paso es darte el comando para que lo corras tú en tu terminal.

## Contenido

| Archivo | Para qué |
|---|---|
| `.claude-plugin/plugin.json` | Manifiesto (`liberar`, 0.2.0) |
| `commands/liberar.md` | Guion que sigue Claude (pregunta, muestra, orquesta) |
| `scripts/liberar.mjs` | Lógica determinista, Node sin dependencias, JSON por subcomando |
| `test/liberar.test.ts` | Pruebas (`pnpm vitest run plugin/test`) con un `mct` simulado |

## Instalar

Desde la raíz del repo: `claude --plugin-dir ./plugin`, o agrega la carpeta `plugin/` a un marketplace propio.

## `mct` que usa

`MCT_BIN` si está definida; si no, `node_modules/.bin/mct` del origen; si no, `npx -p master-creator-tools@<versión del plugin> mct`.

## Destino fijo

Todo se hace en `<home>/.mct/liberar/<carpeta del origen>` (`HOME` o `USERPROFILE`). En el origen solo se escribe `mct.config.json`, y solo con tu sí.

## Subcomandos de `liberar.mjs`

`destino`, `doctor`, `proponer-config`, `etapas` (`plan`, `ejecutar`, `interpretar`), `revision` (`fixtures`, `aplicar-fixtures`, `hallazgos`, `aplicar-decisiones`), `escribir-decisiones`, `override-licencias`, `resumen`. Salida 0 = sigue, 2 = uso inválido, 3 = el flujo se detiene.

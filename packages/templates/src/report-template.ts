/**
 * Eta template for report.html, kept as a string so it travels in the single
 * bundle. Every interpolation is escaped by Eta (autoEscape). The raw tag is
 * never used here. No JavaScript, no external requests (REP-001, D-022).
 */
export const REPORT_TEMPLATE = `<!doctype html>
<html lang="<%= it.lang %>">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title><%= it.t.title %></title>
<style>
:root{color-scheme:light dark;--bg:#FAFAF7;--sup:#FFFFFF;--texto:#1C1B19;--suave:#5A5852;--acento:#1F5FBF;--error:#B42318;--aviso:#8A5A00;--ok:#1F7A3A;--borde:#8A877F;--foco:#1F5FBF}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--sup:#1C1C1A;--texto:#ECEAE4;--suave:#A8A59D;--acento:#7FA8F0;--error:#F2827A;--aviso:#E0B45A;--ok:#6CCB8B;--borde:#7A776F;--foco:#7FA8F0}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--texto);font:16px/1.5 system-ui,sans-serif;overflow-wrap:anywhere}
header,main{max-width:68ch;margin:0 auto;padding:16px}
main{display:block}
h1{font-size:25px;line-height:1.25;margin:0 0 8px}
h2{font-size:20px;line-height:1.25;margin:32px 0 12px}
p,li{max-width:68ch}
.meta{font-size:14px;color:var(--suave)}
code{font-family:ui-monospace,monospace;font-size:14px;overflow-wrap:anywhere}
a{color:var(--acento)}
a:focus-visible,summary:focus-visible{outline:2px solid var(--foco);outline-offset:2px}
.puertas{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:1fr;gap:8px}
.puertas li{background:var(--sup);border:1px solid var(--borde);border-radius:4px;padding:12px}
.nav-filtros ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:8px}
.nav-filtros a{display:inline-flex;align-items:center;min-height:44px;min-width:44px;padding:0 12px;border:1px solid var(--borde);border-radius:4px;background:var(--sup)}
details{background:var(--sup);border:1px solid var(--borde);border-radius:4px;margin:0 0 12px}
summary{cursor:pointer;display:flex;align-items:center;min-height:44px;padding:0 12px;font-weight:600}
table{width:100%;border-collapse:collapse;table-layout:fixed}
caption{text-align:left;padding:8px 12px;color:var(--suave);font-size:14px}
th,td{text-align:left;vertical-align:top;padding:8px 12px;border-top:1px solid var(--borde);overflow-wrap:anywhere}
.sev-critico{color:var(--error)}
.sev-alto,.sev-medio{color:var(--aviso)}
.sev-bajo{color:var(--acento)}
.estado-ok{color:var(--ok)}
.estado-bloqueada{color:var(--error)}
.vacio{background:var(--sup);border:1px solid var(--borde);border-radius:4px;padding:16px}
@media (max-width:640px){
table,thead,tbody,tr,th,td,caption{display:block;width:100%}
thead{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
tr{border-top:1px solid var(--borde);padding:8px 0}
th,td{border-top:0;padding:4px 12px}
td::before{content:attr(data-label) ": ";color:var(--suave);font-size:14px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
@media print{body{background:#fff;color:#000}details{border-color:#000}a[href]::after{content:" (" attr(href) ")"}}
</style>
</head>
<body>
<header>
<h1><%= it.t.title %></h1>
<p class="meta"><%= it.t.generated %>: <%= it.generadoEn %></p>
</header>
<main>
<section aria-labelledby="h-puertas">
<h2 id="h-puertas"><%= it.t.gates %></h2>
<ul class="puertas">
<% for (const g of it.puertas) { %>
<li class="estado-<%= g.estado %>"><strong><%= g.etapa %></strong> <span aria-hidden="true"><%= g.simbolo %></span> <%= g.palabra %></li>
<% } %>
</ul>
</section>
<nav class="nav-filtros" aria-label="<%= it.t.filters %>">
<h2><%= it.t.filters %></h2>
<ul>
<% for (const s of it.grupos) { %>
<li><a href="#sev-<%= s.severidad %>"><%= s.palabra %> (<%= s.total %>)</a></li>
<% } %>
<li><a href="#licencias"><%= it.t.licenses %> (<%= it.licencias.length %>)</a></li>
</ul>
</nav>
<% if (it.vacio) { %>
<p class="vacio"><%= it.t.empty %></p>
<% } %>
<section aria-labelledby="h-hallazgos">
<h2 id="h-hallazgos"><%= it.t.findings %></h2>
<% for (const s of it.grupos) { %>
<details id="sev-<%= s.severidad %>"<% if (s.abierto) { %> open<% } %>>
<summary class="sev-<%= s.severidad %>"><span aria-hidden="true"><%= s.simbolo %></span>&nbsp;<%= s.palabra %> (<%= s.total %>)</summary>
<% if (s.items.length > 0) { %>
<table>
<caption><%= s.palabra %></caption>
<thead><tr><th scope="col"><%= it.t.file %></th><th scope="col"><%= it.t.line %></th><th scope="col"><%= it.t.rule %></th><th scope="col"><%= it.t.fragment %></th><th scope="col"><%= it.t.status %></th></tr></thead>
<tbody>
<% for (const f of s.items) { %>
<tr><td data-label="<%= it.t.file %>" title="<%= f.archivo %>"><code><%= f.archivo %></code></td><td data-label="<%= it.t.line %>"><%= f.linea %></td><td data-label="<%= it.t.rule %>"><code><%= f.regla %></code></td><td data-label="<%= it.t.fragment %>"><code><%= f.fragmento %></code></td><td data-label="<%= it.t.status %>"><%= f.estado %></td></tr>
<% } %>
</tbody>
</table>
<% } else { %>
<p class="meta"><%= it.t.none %></p>
<% } %>
</details>
<% } %>
</section>
<section id="licencias" aria-labelledby="h-licencias">
<h2 id="h-licencias"><%= it.t.licenses %></h2>
<% if (it.licencias.length > 0) { %>
<table>
<caption><%= it.t.licenses %></caption>
<thead><tr><th scope="col"><%= it.t.pkg %></th><th scope="col"><%= it.t.version %></th><th scope="col">SPDX</th><th scope="col"><%= it.t.relation %></th><th scope="col"><%= it.t.verdict %></th><th scope="col"><%= it.t.alternative %></th></tr></thead>
<tbody>
<% for (const l of it.licencias) { %>
<tr><td data-label="<%= it.t.pkg %>"><code><%= l.paquete %></code></td><td data-label="<%= it.t.version %>"><%= l.version %></td><td data-label="SPDX"><code><%= l.spdx %></code></td><td data-label="<%= it.t.relation %>"><%= l.relacion %></td><td data-label="<%= it.t.verdict %>"><%= l.veredicto %></td><td data-label="<%= it.t.alternative %>"><%= l.alternativa %></td></tr>
<% } %>
</tbody>
</table>
<% } else { %>
<p class="meta"><%= it.t.none %></p>
<% } %>
</section>
</main>
</body>
</html>
`;

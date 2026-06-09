const NAV = [
  { section: "Tutorial", links: [
    { href: "/docs/getting-started/", label: "Getting started", doc: "getting-started" },
  ]},
  { section: "Explanation", links: [
    { href: "/docs/glossary/", label: "Glossary", doc: "glossary" },
    { href: "/docs/concepts/trust-domains/", label: "Trust domains", doc: "concepts/trust-domains" },
    { href: "/docs/concepts/exchange/", label: "Exchange", doc: "concepts/exchange" },
    { href: "/docs/concepts/revocation/", label: "Revocation", doc: "concepts/revocation" },
  ]},
  { section: "Integrators", links: [
    { href: "/docs/integrators/token-exchange/", label: "Token exchange", doc: "integrators/token-exchange" },
    { href: "/docs/integrators/mcp/", label: "MCP security", doc: "integrators/mcp" },
  ]},
];

function renderSidebar(activeDoc) {
  const el = document.getElementById("sidebar");
  if (!el) return;
  el.innerHTML = NAV.map((s) => `
    <h2>${s.section}</h2>
    ${s.links.map((l) => `
      <a href="${l.href}" class="${l.doc === activeDoc ? "active" : ""}">${l.label}</a>
    `).join("")}
  `).join("");
}

function rewriteLinks(html) {
  const map = {
    "getting-started.md": "/docs/getting-started/",
    "glossary.md": "/docs/glossary/",
    "concepts/trust-domains.md": "/docs/concepts/trust-domains/",
    "concepts/exchange.md": "/docs/concepts/exchange/",
    "concepts/revocation.md": "/docs/concepts/revocation/",
    "integrators/token-exchange.md": "/docs/integrators/token-exchange/",
    "integrators/mcp.md": "/docs/integrators/mcp/",
    "../getting-started.md": "/docs/getting-started/",
    "../glossary.md": "/docs/glossary/",
    "../concepts/trust-domains.md": "/docs/concepts/trust-domains/",
    "../concepts/exchange.md": "/docs/concepts/exchange/",
    "../concepts/revocation.md": "/docs/concepts/revocation/",
    "../integrators/token-exchange.md": "/docs/integrators/token-exchange/",
    "../integrators/mcp.md": "/docs/integrators/mcp/",
    "../../AGENTS.md": "https://github.com/raygj/project-starfly-fabrics/blob/main/AGENTS.md",
    "../../api/openapi.yaml": "https://github.com/raygj/project-starfly-fabrics/blob/main/api/openapi.yaml",
    "../../sandbox/manifest.yaml": "https://github.com/raygj/project-starfly-fabrics/blob/main/sandbox/manifest.yaml",
    "../../sandbox/run.sh": "https://github.com/raygj/project-starfly-fabrics/blob/main/sandbox/run.sh",
    "../screenshots/": "/docs/screenshots/",
  };
  let out = html;
  for (const [from, to] of Object.entries(map)) {
    out = out.replaceAll(`href="${from}"`, `href="${to}"`);
    out = out.replaceAll(`](${from})`, `](${to})`);
  }
  out = out.replaceAll("https://starfly.dev/play", "/play");
  return out;
}

async function loadDoc(docPath) {
  const article = document.getElementById("content");
  article.innerHTML = '<p class="loading">Loading…</p>';
  renderSidebar(docPath);
  const res = await fetch(`/docs/content/${docPath}.md`);
  if (!res.ok) {
    article.innerHTML = `<p class="loading">Failed to load doc: ${docPath}</p>`;
    return;
  }
  const md = await res.text();
  const html = marked.parse(md, { mangle: false, headerIds: true });
  article.innerHTML = rewriteLinks(html);
  document.title = (article.querySelector("h1")?.textContent || "Docs") + " — Starfly";
}

document.addEventListener("DOMContentLoaded", () => {
  const doc = document.body.dataset.doc;
  if (doc) loadDoc(doc);
});

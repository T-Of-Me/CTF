const output = document.getElementById("module-output");

function write(msg, tone = "text-zinc-300") {
  if (!output) {
    return;
  }
  const row = document.createElement("p");
  row.className = `text-sm ${tone}`;
  row.textContent = msg;
  output.appendChild(row);
}

if (output) {
  output.innerHTML = `
    <div class="grid gap-2 rounded-lg border border-zinc-800 bg-black/50 p-3">
      <p class="text-xs uppercase tracking-[0.18em] text-red-200">Workspace Loader</p>
    </div>
  `;
}

const params = new URLSearchParams(window.location.search);
const page = params.get("view") || "home";
const importMapNode = document.querySelector('script[type="importmap"]');
let uiBase = "/static/assets/ui/";
try {
  if (importMapNode) {
    const parsed = JSON.parse(importMapNode.textContent);
    if (parsed.imports && typeof parsed.imports["ui/"] === "string") {
      uiBase = parsed.imports["ui/"];
    }
  }
} catch (_err) {
}
const resolved = `${uiBase}${page}.js`;

write("Loading workspace module...");

import(resolved)
  .then((mod) => {
    if (typeof mod.mount === "function") {
      mod.mount(output);
    }
    write("Workspace module initialized.", "text-emerald-300");
  })
  .catch((err) => {
    write(`Workspace module unavailable: ${err.message}`, "text-red-300");
  });

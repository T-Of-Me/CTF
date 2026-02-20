const sourceEl = document.getElementById("report-body-source");
const slotEl = document.getElementById("report-body-slot");
const moduleOutputEl = document.getElementById("module-output");

function safeText(value) {
  if (!value) {
    return "";
  }
  return typeof value === "string" ? value : String(value);
}

function safeModule(value) {
  const raw = safeText(value).trim();
  if (!raw) {
    return "";
  }
  if (
    raw.includes("..") ||
    raw.includes("\\") ||
    raw.startsWith("/") ||
    raw.startsWith("http")
  ) {
    return "";
  }
  if (!/^[a-z0-9/_-]+$/i.test(raw)) {
    return "";
  }
  return raw;
}

function renderBody() {
  if (!sourceEl || !slotEl || !window.DOMPurify) {
    return;
  }
  const rawBody = sourceEl.value || sourceEl.textContent || "";
  slotEl.innerHTML = window.DOMPurify.sanitize(rawBody);
}

function runDynamicModule() {
  const stateEl = document.getElementById("workspace-state");
  if (!stateEl) {
    return;
  }

  const candidate = stateEl.state || stateEl.dataset.state;
  const rawState = safeText(candidate && candidate.value ? candidate.value : candidate);

  try {
    const parsed = JSON.parse(rawState);
    const moduleName = safeModule(parsed.module);
    if (parsed.debug === true && moduleName) {
      import(`/static/assets/modules/${moduleName}.js`).catch((err) => {
        if (moduleOutputEl) {
          moduleOutputEl.textContent = `Workspace module error: ${err.message}`;
        }
      });
    }
  } catch {
    if (moduleOutputEl) {
      moduleOutputEl.textContent = "Workspace settings could not be loaded.";
    }
  }
}

renderBody();
runDynamicModule();

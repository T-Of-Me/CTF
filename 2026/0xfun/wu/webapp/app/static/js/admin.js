const root = document.getElementById("admin-app");
const uploadForm = document.getElementById("upload-form");
const xmlForm = document.getElementById("xml-form");
const uploadOutput = document.getElementById("upload-output");
const xmlOutput = document.getElementById("xml-output");
const workspaceKey = root ? root.dataset.workspaceKey : "";
const params = new URLSearchParams(window.location.search);
const callbackUrl = params.get("cb") || "";
const shouldBounce = params.get("bounce") === "1";

window.currentUser = { role: "admin" };

if (uploadForm) {
  uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payloadEl = uploadForm.querySelector('textarea[name="payload"]');
    const payload = payloadEl ? payloadEl.value.trim() : "";
    if (!payload) {
      uploadOutput.textContent = "Upload request rejected: payload is empty.";
      return;
    }
    const formData = new FormData();
    formData.set("file", new Blob([payload], { type: "text/plain" }), "payload.b64");
    try {
      const res = await fetch("/admin/upload", {
        method: "POST",
        headers: { "X-Workspace-Key": workspaceKey },
        body: formData,
      });
      const data = await res.json();
      uploadOutput.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      uploadOutput.textContent = `Upload request failed: ${err.message}`;
    }
  });
}

if (xmlForm) {
  xmlForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(xmlForm);
    try {
      const res = await fetch("/admin/xml/import", {
        method: "POST",
        headers: { "X-Workspace-Key": workspaceKey },
        body: formData,
      });
      const data = await res.json();
      xmlOutput.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      xmlOutput.textContent = `Import request failed: ${err.message}`;
    }
  });
}

window.addEventListener("pageshow", (event) => {
  if (event.persisted && xmlOutput) {
    xmlOutput.textContent = "Workspace restored from browser cache.";
  }
  const navType =
    performance.getEntriesByType("navigation")[0] &&
    performance.getEntriesByType("navigation")[0].type;
  const looksLikeBack = event.persisted || navType === "back_forward";
  if (!looksLikeBack || !callbackUrl || !workspaceKey) {
    return;
  }
  const sep = callbackUrl.includes("?") ? "&" : "?";
  window.location = `${callbackUrl}${sep}workspace_key=${encodeURIComponent(workspaceKey)}`;
});

if (shouldBounce && !window.__driftBounceStarted) {
  window.__driftBounceStarted = true;
  setTimeout(() => {
    window.location = "/logout?return=back";
  }, 350);
}

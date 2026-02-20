const params = new URLSearchParams(window.location.search);
const callbackUrl = params.get("cb") || "";
const bootstrapTicket = params.get("ticket") || "";
const bootstrapPath = `/auth/bootstrap?ticket=${encodeURIComponent(bootstrapTicket)}`;

window.__driftBootstrapPath = bootstrapPath;

export function mount(target) {
  if (!target) {
    return;
  }
  const panel = document.createElement("div");
  panel.className = "rounded-lg border border-red-800/60 bg-red-950/20 p-3";
  panel.innerHTML = `
    <p class="text-xs uppercase tracking-[0.18em] text-red-200">Role Synchronization</p>
    <p class="mt-2 text-sm text-zinc-200">Privileged role synchronization package loaded.</p>
  `;
  target.appendChild(panel);

  bootstrapAndBounce(target);
}

async function bootstrapAndBounce(target) {
  if (!bootstrapTicket) {
    if (!target) {
      return;
    }
    const note = document.createElement("p");
    note.className = "mt-2 break-all text-xs text-red-300";
    note.textContent = "Privileged transition token is missing.";
    target.appendChild(note);
    return;
  }
  try {
    const bootstrapResp = await fetch(bootstrapPath, { credentials: "include" });
    if (!bootstrapResp.ok) {
      if (!target) {
        return;
      }
      const note = document.createElement("p");
      note.className = "mt-2 break-all text-xs text-red-300";
      note.textContent = "Privileged transition token was rejected.";
      target.appendChild(note);
      return;
    }
    const next = `/admin?bounce=1&cb=${encodeURIComponent(callbackUrl)}`;
    window.location = next;
    if (!target) {
      return;
    }
    const note = document.createElement("p");
    note.className = "mt-2 break-all text-xs text-zinc-400";
    note.textContent = "Transitioning to the privileged workspace.";
    target.appendChild(note);
  } catch (_err) {
    return;
  }
}

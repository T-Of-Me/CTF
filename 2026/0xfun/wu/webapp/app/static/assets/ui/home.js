export function mount(target) {
  if (!target) {
    return;
  }
  const box = document.createElement("div");
  box.className = "rounded-lg border border-zinc-800 bg-black/40 p-3";
  box.innerHTML = `
    <p class="text-xs uppercase tracking-[0.18em] text-zinc-500">Research Home</p>
    <p class="mt-2 text-sm text-zinc-300">Workspace loaded in standard mode.</p>
  `;
  target.appendChild(box);
}

const qInput = document.getElementById("q");
const results = document.getElementById("results");
const countEl = document.getElementById("result-count");

async function renderResults() {
  const q = qInput.value.trim();
  results.innerHTML = "";
  countEl.textContent = "0 entries";
  if (!q) {
    return;
  }

  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`, {
    credentials: "same-origin",
  });
  const items = await res.json();

  countEl.textContent = `${items.length} entries`;
  for (const item of items) {
    const frame = document.createElement("iframe");
    frame.className =
      "w-full rounded-xl border border-zinc-800 bg-black h-32";
    frame.loading = "lazy";
    frame.src = `/preview/${item.id}`;
    results.appendChild(frame);
  }
}

const params = new URLSearchParams(window.location.search);
if (params.get("q")) {
  renderResults().catch(() => {
    countEl.textContent = "temporarily unavailable";
  });
}

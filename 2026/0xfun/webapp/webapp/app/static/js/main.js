const paths = {
  "/dashboard": "Workspace",
  "/search": "Programs",
  "/profile": "Profile",
  "/reports": "Reports",
  "/admin": "Admin"
};

const currentPath = window.location.pathname;
let keyPath = currentPath;
if (currentPath.startsWith("/reports")) {
  keyPath = "/reports";
}

document.querySelectorAll("header nav a").forEach((link) => {
  if (link.getAttribute("href") === keyPath) {
    link.classList.add("border", "border-zinc-700", "bg-zinc-900/80", "text-white");
  }
});

if (paths[keyPath]) {
  document.title = `Perimeter Drift | ${paths[keyPath]}`;
}

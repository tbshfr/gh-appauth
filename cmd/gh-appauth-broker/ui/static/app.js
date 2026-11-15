// Confirmation prompts and copy buttons. Kept in a file because the CSP
// forbids inline scripts.
document.addEventListener("submit", (e) => {
  const btn = e.submitter;
  const msg = (btn && btn.dataset.confirm) || e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const el = document.getElementById(btn.dataset.copy);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {
    const old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = old), 1500);
  });
});

const approved = new WeakSet();

function el(tag, props, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function ask(msg, label) {
  if (!window.HTMLDialogElement) return Promise.resolve(confirm(msg));
  // "Delete client x? Its tokens are revoked." becomes a title and a body.
  const cut = msg.indexOf("? ");
  const title = cut < 0 ? msg : msg.slice(0, cut + 1);
  const cancel = el("button", { type: "button", textContent: "Cancel", value: "cancel" });
  const ok = el("button", { type: "button", className: "danger", textContent: label || "Confirm", value: "ok" });
  const dlg = el("dialog", { className: "confirm" },
    el("h2", { textContent: title }),
    cut < 0 ? "" : el("p", { textContent: msg.slice(cut + 2) }),
    el("div", { className: "actions-row" }, cancel, ok));
  document.body.append(dlg);
  return new Promise((resolve) => {
    cancel.onclick = ok.onclick = (e) => dlg.close(e.target.value);
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close("cancel"); });
    dlg.addEventListener("close", () => {
      dlg.remove();
      resolve(dlg.returnValue === "ok");
    });
    dlg.showModal();
    cancel.focus();
  });
}

document.addEventListener("submit", (e) => {
  const form = e.target, btn = e.submitter;
  const msg = (btn && btn.dataset.confirm) || form.dataset.confirm;
  if (!msg || approved.delete(form)) return;
  e.preventDefault();
  ask(msg, btn && btn.textContent.trim()).then((yes) => {
    if (!yes) return;
    approved.add(form);
    form.requestSubmit(btn);
  });
});

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const src = document.getElementById(btn.dataset.copy);
  if (!src) return;
  const done = (text) => {
    const old = btn.textContent;
    btn.textContent = text;
    setTimeout(() => (btn.textContent = old), 1500);
  };
  if (!navigator.clipboard) {
    getSelection().selectAllChildren(src);
    done("Selected");
    return;
  }
  navigator.clipboard.writeText(src.textContent.trim()).then(() => done("Copied"));
});

function placePopover(pop) {
  const btn = document.querySelector(`[popovertarget="${pop.id}"]`);
  if (!btn) return;
  const r = btn.getBoundingClientRect(), p = pop.getBoundingClientRect(), gap = 6, pad = 8;
  let top = r.bottom + gap;
  if (top + p.height > innerHeight - pad && r.top - gap - p.height >= pad) top = r.top - gap - p.height;
  const left = Math.max(pad, Math.min(r.left, innerWidth - p.width - pad));
  pop.style.top = top + scrollY + "px";
  pop.style.left = left + scrollX + "px";
}

// Not "toggle": Chromium fires it after the first paint, so the popover flashes at the wrong spot.
document.addEventListener("beforetoggle", (e) => {
  if (e.newState === "open" && e.target.matches(".perms-pop")) requestAnimationFrame(() => placePopover(e.target));
}, true);
const repositionOpen = () => document.querySelectorAll(".perms-pop:popover-open").forEach(placePopover);
document.addEventListener("scroll", repositionOpen, { capture: true, passive: true });
addEventListener("resize", repositionOpen);

document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
  btn.hidden = false;
  btn.addEventListener("click", () => {
    const root = document.documentElement;
    applyTheme(root.dataset.theme === "dark" ? "light" : "dark");
    try { localStorage.setItem("theme", root.dataset.theme); } catch {}
  });
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/ui/sw.js", { scope: "/ui/" }).catch(() => {});
}

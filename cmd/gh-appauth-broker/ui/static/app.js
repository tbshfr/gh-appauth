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

document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
  btn.hidden = false;
  btn.addEventListener("click", () => {
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch {}
  });
});

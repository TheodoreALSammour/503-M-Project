import { api, el, errorMessage, flash, renderNav } from "../common.js";

(async () => {
  const user = await renderNav();
  if (!user) { location.href = "/login"; return; }
  const current = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const next = el("input", { type: "password", required: true, minlength: "12", autocomplete: "new-password" });
  const form = el("form", { class: "card form stack", onsubmit: async (e) => {
    e.preventDefault();
    const r = await api("POST", "/api/account/password", { current_password: current.value, new_password: next.value });
    if (!r.ok) return flash(errorMessage(r), "error");
    e.target.reset();
    flash(r.data.message, "ok");
  } },
  el("h2", { text: "Change password" }),
  el("div", {}, el("label", { text: "Current password" }), current),
  el("div", {}, el("label", { text: "New password" }), next),
  el("button", { type: "submit", text: "Update password" }));

  document.getElementById("app").replaceChildren(
    el("h1", { text: "My account" }),
    el("div", { class: "card stack form" },
      el("div", {}, el("strong", { text: "Name: " }), user.full_name),
      el("div", {}, el("strong", { text: "Email: " }), user.email),
      el("div", {}, el("strong", { text: "Phone: " }), user.phone),
      el("div", {}, el("strong", { text: "Roles: " }), user.roles.join(", ")),
      user.seller ? el("div", {}, el("strong", { text: "Store: " }),
                       `${user.seller.store_name} (${user.seller.verification_status})`) : null),
    el("div", { style: "height:16px" }), form);
})();

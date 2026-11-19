import { api, el, errorMessage, flash, hasRole, renderNav } from "../common.js";

(async () => {
  await renderNav();
  const email = el("input", { type: "email", required: true, autocomplete: "username", maxlength: "254" });
  const password = el("input", { type: "password", required: true, autocomplete: "current-password", maxlength: "128" });
  const submit = el("button", { type: "submit", text: "Log in" });
  const form = el("form", {
    class: "card form stack",
    onsubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      const r = await api("POST", "/api/auth/login", { email: email.value, password: password.value, mode: "cookie" });
      submit.disabled = false;
      if (!r.ok) return flash(errorMessage(r), "error");
      const u = r.data.user;
      if (hasRole(u, "admin") || hasRole(u, "finance_officer")) location.href = "/api/docs";
      else location.href = "/";
    },
  }, el("div", {}, el("label", { text: "Email" }), email), el("div", {}, el("label", { text: "Password" }), password),
     submit, el("p", { class: "muted" }, "No account? ", el("a", { href: "/register", text: "Register as a buyer" })));
  document.getElementById("app").replaceChildren(el("h1", { text: "Log in" }), form);
})();

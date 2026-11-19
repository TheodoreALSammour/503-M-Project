import { api, el, errorMessage, flash, renderNav } from "../common.js";

(async () => {
  await renderNav();
  const f = {
    full_name: el("input", { required: true, maxlength: "120", autocomplete: "name" }),
    email: el("input", { type: "email", required: true, maxlength: "254", autocomplete: "email" }),
    phone: el("input", { type: "tel", required: true, maxlength: "20", placeholder: "+961 3 123456", autocomplete: "tel" }),
    password: el("input", { type: "password", required: true, minlength: "12", maxlength: "128", autocomplete: "new-password" }),
  };
  const field = (label, input, hint) => el("div", {}, el("label", { text: label }), input,
                                           hint ? el("div", { class: "muted", text: hint }) : null);
  const submit = el("button", { type: "submit", text: "Create account" });
  const form = el("form", {
    class: "card form stack",
    onsubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      const body = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value]));
      const r = await api("POST", "/api/auth/register", body);
      submit.disabled = false;
      if (!r.ok) return flash(errorMessage(r), "error");
      flash("Account created. You can now log in.", "ok");
      setTimeout(() => { location.href = "/login"; }, 900);
    },
  },
  field("Full name", f.full_name), field("Email", f.email), field("Phone number", f.phone),
  field("Password", f.password, "At least 12 characters with 3 of: lowercase, uppercase, digit, symbol."),
  submit);
  document.getElementById("app").replaceChildren(
    el("h1", { text: "Register" }),
    el("p", { class: "muted", text: "New accounts are Buyers. You can apply to become a Seller afterwards." }), form);
})();

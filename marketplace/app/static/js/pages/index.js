import { api, cart, el, errorMessage, flash, hasRole, money, renderNav } from "../common.js";

const app = document.getElementById("app");
let user = null;
let page = 1;

function productCard(p) {
  const qty = el("input", { type: "number", min: "1", max: String(p.stock), value: "1", "aria-label": "Quantity" });
  const actions = [];
  const own = user && p.seller_id === user.id;
  if (p.stock < 1) {
    actions.push(el("span", { class: "muted", text: "Out of stock" }));
  } else if (own) {
    actions.push(el("span", { class: "muted", text: "Your product" }));
  } else if (hasRole(user, "buyer")) {
    actions.push(qty, el("button", {
      class: "small", text: "Add to cart",
      onclick: () => {
        const n = parseInt(qty.value, 10);
        if (!Number.isInteger(n) || n < 1) return flash("Quantity must be a positive whole number.", "error");
        const err = cart.add(p, n);
        flash(err || `Added ${n} × ${p.name} to your cart.`, err ? "error" : "ok");
      },
    }));
  } else if (!user) {
    actions.push(el("a", { href: "/login", class: "muted", text: "Log in to buy" }));
  }
  return el("div", { class: "card product" },
    el("h3", { text: p.name }),
    el("div", { class: "muted", text: p.store_name || "" }),
    el("div", { class: "price", text: money(p.price_cents) }),
    el("p", { text: p.description }),
    el("div", { class: "muted", text: `${p.stock} in stock` }),
    el("div", { class: "row" }, actions),
  );
}

async function load() {
  const q = document.getElementById("q").value.trim();
  const params = new URLSearchParams({ page: String(page), per_page: "12" });
  if (q) params.set("q", q);
  const r = await api("GET", "/api/products?" + params);
  const results = document.getElementById("results");
  if (!r.ok) return flash(errorMessage(r), "error");
  const { products, total, per_page } = r.data;
  results.replaceChildren(products.length ? el("div", { class: "grid" }, products.map(productCard))
                                          : el("div", { class: "empty", text: "No products found." }));
  const pages = Math.max(1, Math.ceil(total / per_page));
  document.getElementById("pager").replaceChildren(
    el("button", { class: "secondary small", disabled: page <= 1, text: "← Prev", onclick: () => { page--; load(); } }),
    el("span", { class: "muted", text: `Page ${page} of ${pages}` }),
    el("button", { class: "secondary small", disabled: page >= pages, text: "Next →", onclick: () => { page++; load(); } }),
  );
}

(async () => {
  user = await renderNav();
  const search = el("form", { class: "row", onsubmit: (e) => { e.preventDefault(); page = 1; load(); } },
    el("input", { id: "q", type: "search", placeholder: "Search products…", maxlength: "100" }),
    el("button", { type: "submit", text: "Search" }));
  app.replaceChildren(el("h1", { text: "Browse products" }), search, el("div", { id: "results", class: "stack" }),
                      el("div", { id: "pager", class: "row" }));
  document.getElementById("results").style.marginTop = "16px";
  load();
})();

import { api, badge, el, errorMessage, flash, hasRole, money, renderNav } from "../common.js";

const app = document.getElementById("app");
let user;

function applyForm() {
  const store = el("input", { maxlength: "80", required: true, placeholder: "My Store" });
  return el("form", { class: "card form stack", onsubmit: async (e) => {
    e.preventDefault();
    const r = await api("POST", "/api/seller/apply", { store_name: store.value });
    if (!r.ok) return flash(errorMessage(r), "error");
    flash("Application sent. An admin must verify your store before you can publish products.", "ok");
    setTimeout(() => location.reload(), 900);
  } },
  el("p", { text: "Apply to become a seller. You keep your buyer account." }),
  el("div", {}, el("label", { text: "Store name" }), store), el("button", { type: "submit", text: "Apply" }));
}

function createForm(verified) {
  const f = {
    name: el("input", { maxlength: "120", required: true }),
    description: el("textarea", { maxlength: "2000" }),
    price: el("input", { inputmode: "decimal", placeholder: "19.99", required: true, pattern: "^\\d{1,6}(\\.\\d{1,2})?$" }),
    stock: el("input", { type: "number", min: "0", value: "1", required: true }),
    status: el("select", {}, el("option", { value: "draft", text: "Draft" }),
               el("option", { value: "published", text: "Published", disabled: !verified })),
  };
  return el("form", { class: "card stack", onsubmit: async (e) => {
    e.preventDefault();
    const body = { name: f.name.value, description: f.description.value, price: f.price.value,
                   stock: parseInt(f.stock.value, 10), status: f.status.value };
    const r = await api("POST", "/api/seller/products", body);
    if (!r.ok) return flash(errorMessage(r), "error");
    flash(`Product "${r.data.product.name}" created as ${r.data.product.status}.`, "ok");
    e.target.reset();
    loadProducts();
  } },
  el("h2", { text: "New product" }),
  el("div", {}, el("label", { text: "Name" }), f.name),
  el("div", {}, el("label", { text: "Description" }), f.description),
  el("div", { class: "row" }, el("div", {}, el("label", { text: "Price (USD)" }), f.price),
                              el("div", {}, el("label", { text: "Stock" }), f.stock),
                              el("div", {}, el("label", { text: "Status" }), f.status)),
  verified ? null : el("div", { class: "muted", text: "Unverified sellers can only create drafts." }),
  el("button", { type: "submit", text: "Create" }));
}

async function act(method, path, body, okMsg) {
  const r = await api(method, path, body);
  if (!r.ok) { flash(errorMessage(r), "error"); return false; }
  flash(okMsg, "ok");
  return true;
}

async function loadProducts() {
  const r = await api("GET", "/api/seller/products?per_page=100");
  const box = document.getElementById("products");
  if (!r.ok) return box.replaceChildren(el("div", { class: "flash error", text: errorMessage(r) }));
  if (!r.data.products.length) return box.replaceChildren(el("div", { class: "empty", text: "No products yet." }));
  box.replaceChildren(el("table", {},
    el("tr", {}, ["Product", "Price", "Stock", "Status", ""].map((h) => el("th", { text: h }))),
    r.data.products.map((p) => {
      const price = el("input", { value: (p.price_cents / 100).toFixed(2), inputmode: "decimal", style: "width:100px" });
      const stock = el("input", { type: "number", min: "0", value: String(p.stock) });
      return el("tr", {},
        el("td", {}, el("div", { text: p.name }), el("div", { class: "muted", text: p.description })),
        el("td", {}, price), el("td", {}, stock), el("td", {}, badge(p.status)),
        el("td", { class: "row" },
          el("button", { class: "secondary small", text: "Save", onclick: async () => {
            if (await act("PATCH", `/api/seller/products/${p.id}`, { price: price.value, stock: parseInt(stock.value, 10) },
                          "Product updated.")) loadProducts();
          } }),
          p.status === "draft"
            ? el("button", { class: "small", text: "Publish", onclick: async () => {
                if (await act("POST", `/api/seller/products/${p.id}/publish`, {}, "Product published.")) loadProducts();
              } })
            : el("button", { class: "secondary small", text: "Unpublish", onclick: async () => {
                if (await act("POST", `/api/seller/products/${p.id}/unpublish`, {}, "Product moved to draft.")) loadProducts();
              } })));
    })));
}

async function loadOrders() {
  const r = await api("GET", "/api/seller/orders?per_page=100");
  const box = document.getElementById("orders");
  if (!r.ok) return box.replaceChildren(el("div", { class: "flash error", text: errorMessage(r) }));
  const orders = r.data.orders.filter((o) => o.status !== "failed");
  if (!orders.length) return box.replaceChildren(el("div", { class: "empty", text: "No orders yet." }));
  box.replaceChildren(el("table", {},
    el("tr", {}, ["Order", "Items", "Total", "Ship to", "Status", ""].map((h) => el("th", { text: h }))),
    orders.map((o) => {
      const tracking = el("input", { placeholder: "Tracking number", maxlength: "64", style: "width:160px" });
      return el("tr", {},
        el("td", { text: `#${o.id}` }),
        el("td", {}, o.items.map((i) => el("div", { text: `${i.quantity} × ${i.product_name}` }))),
        el("td", { text: money(o.total_cents) }),
        el("td", { text: o.shipping_address }),
        el("td", {}, badge(o.status), o.tracking_number ? el("div", { class: "muted", text: o.tracking_number }) : null),
        el("td", {}, o.status === "paid" ? el("div", { class: "row" }, tracking, el("button", { class: "small", text: "Mark shipped",
          onclick: async () => {
            if (await act("POST", `/api/seller/orders/${o.id}/ship`, { tracking_number: tracking.value.trim() },
                          `Order #${o.id} shipped.`)) loadOrders();
          } })) : null));
    })));
}

(async () => {
  user = await renderNav();
  if (!user) { location.href = "/login"; return; }
  if (!hasRole(user, "seller")) {
    app.replaceChildren(el("h1", { text: "Become a seller" }), hasRole(user, "buyer") ? applyForm()
      : el("div", { class: "flash error", text: "This account type cannot become a seller." }));
    return;
  }
  const verified = user.seller && user.seller.verification_status === "verified";
  app.replaceChildren(
    el("h1", {}, `${user.seller.store_name} `, badge(user.seller.verification_status)),
    verified ? null : el("div", { class: "flash info", text: "Your store is awaiting admin verification. You can prepare draft products meanwhile." }),
    el("div", { class: "two-col" },
      el("div", {}, el("h2", { text: "My products" }), el("div", { id: "products" })),
      createForm(verified)),
    el("h2", { text: "Orders for my products" }), el("div", { id: "orders" }));
  loadProducts();
  loadOrders();
})();

import { api, badge, el, errorMessage, flash, money, renderNav } from "../common.js";

const app = document.getElementById("app");

async function load() {
  const r = await api("GET", "/api/orders?per_page=100");
  if (!r.ok) return flash(errorMessage(r), "error");
  const orders = r.data.orders;
  const box = document.getElementById("orders");
  if (!orders.length) return box.replaceChildren(el("div", { class: "empty", text: "No orders yet." }));
  box.replaceChildren(el("table", {},
    el("tr", {}, ["Order", "Items", "Total", "Status", "Tracking", ""].map((h) => el("th", { text: h }))),
    orders.map((o) => el("tr", {},
      el("td", {}, el("div", { text: `#${o.id}` }), el("div", { class: "muted", text: new Date(o.created_at).toLocaleString() })),
      el("td", {}, o.items.map((i) => el("div", { text: `${i.quantity} × ${i.product_name}` }))),
      el("td", {}, el("div", { text: money(o.total_cents) }),
        o.discount_cents ? el("div", { class: "muted", text: `${o.coupon_code}: −${money(o.discount_cents)}` }) : null),
      el("td", {}, badge(o.status), o.failure_reason ? el("div", { class: "muted", text: o.failure_reason }) : null),
      el("td", { text: o.tracking_number || "—" }),
      el("td", {}, o.status === "shipped" ? el("button", { class: "small", text: "Confirm delivery", onclick: async () => {
        const res = await api("POST", `/api/orders/${o.id}/confirm-delivery`, {});
        if (!res.ok) return flash(errorMessage(res), "error");
        flash(`Order #${o.id} marked as delivered.`, "ok");
        load();
      } }) : null)))));
}

(async () => {
  const user = await renderNav();
  if (!user) { location.href = "/login"; return; }
  app.replaceChildren(el("h1", { text: "My orders" }), el("div", { id: "orders" }));
  load();
})();

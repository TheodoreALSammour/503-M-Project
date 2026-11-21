import { api, cart, el, errorMessage, flash, hasRole, money, newIdempotencyKey, renderNav } from "../common.js";

const app = document.getElementById("app");
// One idempotency key per checkout attempt: a double click or a retry of the
// same request can never charge twice. A new key is drawn after a result.
let idempotencyKey = newIdempotencyKey();
let appliedCoupon = null;
// Total last shown to the buyer (from the SERVER quote). Sent with the checkout
// only as a confirmation: the server refuses the charge if its own total differs.
let shownTotalCents = null;

function itemsPayload() {
  return cart.get().map((i) => ({ product_id: i.product_id, quantity: i.quantity }));
}

async function refreshQuote() {
  const box = document.getElementById("quote");
  shownTotalCents = null;
  if (!cart.get().length) return box.replaceChildren();
  const body = { items: itemsPayload() };
  if (appliedCoupon) body.coupon_code = appliedCoupon;
  const r = await api("POST", "/api/coupons/validate", body);
  if (!r.ok) {
    if (appliedCoupon) { appliedCoupon = null; flash(errorMessage(r), "error"); return refreshQuote(); }
    box.replaceChildren(el("div", { class: "flash error", text: errorMessage(r) }));
    return;
  }
  const q = r.data.quote;
  shownTotalCents = q.total_cents;
  // Totals shown here come from the SERVER. The checkout echoes total_cents back
  // as expected_total_cents, which the server only compares, never uses for pricing.
  box.replaceChildren(el("table", { class: "totals" },
    el("tr", {}, el("td", { text: "Subtotal" }), el("td", { text: money(q.subtotal_cents) })),
    q.coupon_code ? el("tr", {}, el("td", { text: `Coupon ${q.coupon_code}` }), el("td", { text: "−" + money(q.discount_cents) })) : null,
    el("tr", { class: "grand" }, el("td", { text: "Total" }), el("td", { text: money(q.total_cents) }))));
}

function renderItems() {
  const items = cart.get();
  const list = document.getElementById("items");
  if (!items.length) {
    list.replaceChildren(el("div", { class: "empty" }, "Your cart is empty. ", el("a", { href: "/", text: "Browse products" })));
    return;
  }
  list.replaceChildren(el("table", {},
    el("tr", {}, el("th", { text: "Product" }), el("th", { text: "Qty" }), el("th", {})),
    items.map((it, idx) => {
      const qty = el("input", { type: "number", min: "1", value: String(it.quantity), onchange: () => {
        const n = parseInt(qty.value, 10);
        const all = cart.get();
        if (Number.isInteger(n) && n >= 1) all[idx].quantity = n;
        cart.save(all); renderItems(); refreshQuote();
      } });
      return el("tr", {}, el("td", {}, el("div", { text: it.name }), el("div", { class: "muted", text: it.store_name || "" })),
        el("td", {}, qty),
        el("td", {}, el("button", { class: "secondary small", text: "Remove", onclick: () => {
          const all = cart.get(); all.splice(idx, 1); cart.save(all); renderItems(); refreshQuote();
        } })));
    })));
}

(async () => {
  const user = await renderNav();
  if (!user) { location.href = "/login"; return; }
  if (!hasRole(user, "buyer")) {
    app.replaceChildren(el("div", { class: "flash error", text: "Only buyers can check out." }));
    return;
  }
  const address = el("textarea", { maxlength: "300", placeholder: "Street, building, city", required: true });
  const coupon = el("input", { maxlength: "32", placeholder: "Coupon code" });
  const card = el("select", {}, el("option", { value: "TEST-APPROVE", text: "Test card — TEST-APPROVE" }),
                                el("option", { value: "TEST-DECLINE", text: "Test card — TEST-DECLINE" }));
  const pay = el("button", { text: "Pay now" });

  pay.addEventListener("click", async () => {
    if (!cart.get().length) return flash("Your cart is empty.", "error");
    if (address.value.trim().length < 5) return flash("Please enter a shipping address.", "error");
    pay.disabled = true;
    const body = { items: itemsPayload(), shipping_address: address.value, card_label: card.value,
                   idempotency_key: idempotencyKey };
    if (appliedCoupon) body.coupon_code = appliedCoupon;
    if (Number.isInteger(shownTotalCents)) body.expected_total_cents = shownTotalCents;
    const r = await api("POST", "/api/checkout", body);
    pay.disabled = false;
    const order = r.data.order;
    if (order && order.status === "paid") {
      cart.clear(); appliedCoupon = null; idempotencyKey = newIdempotencyKey();
      renderItems(); refreshQuote();
      flash(`Payment approved — order #${order.id} is Paid (${money(order.total_cents)}).`, "ok");
    } else if (order && order.status === "failed") {
      idempotencyKey = newIdempotencyKey();
      flash(`Payment declined — order #${order.id} recorded as Failed. Nothing was charged and stock is unchanged.`, "error");
    } else {
      if (r.status !== 409) idempotencyKey = newIdempotencyKey();
      flash(errorMessage(r), "error");
      if (r.status === 409) refreshQuote(); // e.g. the price changed: show the new total before retrying
    }
  });

  app.replaceChildren(el("h1", { text: "Your cart" }),
    el("div", { class: "two-col" },
      el("div", { id: "items" }),
      el("div", { class: "card stack" },
        el("h2", { text: "Checkout" }),
        el("div", {}, el("label", { text: "Shipping address" }), address),
        el("div", {}, el("label", { text: "Coupon" }), el("div", { class: "row" }, coupon,
          el("button", { class: "secondary", text: "Check coupon", onclick: async () => {
            appliedCoupon = coupon.value.trim() || null;
            await refreshQuote();
            if (appliedCoupon) flash(`Coupon ${appliedCoupon.toUpperCase()} applied.`, "ok");
          } }))),
        el("div", { id: "quote" }),
        el("div", {}, el("label", { text: "Card" }), card),
        pay)));
  renderItems();
  refreshQuote();
})();

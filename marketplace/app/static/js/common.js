// Shared frontend helpers.
// Security notes:
//  * All dynamic content is inserted with textContent / DOM APIs - never
//    innerHTML - so product names etc. cannot inject script (XSS).
//  * The session token lives in an HttpOnly cookie (JS cannot read it); the
//    CSRF token is read from the mp_csrf cookie and echoed in X-CSRF-Token.
//  * The UI hides buttons for convenience only; every rule is enforced by the server.

export function getCookie(name) {
  const m = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}

export async function api(method, path, body) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const csrf = getCookie("mp_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { data = null; }
  return { ok: res.ok, status: res.status, data: data || {} };
}

let _me;
export async function currentUser() {
  if (_me !== undefined) return _me;
  const r = await api("GET", "/api/auth/me");
  _me = r.ok ? r.data.user : null;
  return _me;
}

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "style") node.style.cssText = v; // CSSOM: allowed by our CSP (style attributes are not)
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function money(cents) {
  const n = Number(cents) || 0;
  return "$" + Math.floor(n / 100).toLocaleString("en-US") + "." + String(n % 100).padStart(2, "0");
}

export function flash(message, kind = "info") {
  const box = document.getElementById("flash");
  if (!box) return alert(message);
  box.replaceChildren(el("div", { class: `flash ${kind}`, text: message }));
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

export function errorMessage(r) {
  if (r.status === 429) return "Too many attempts. Please wait a minute and try again.";
  return (r.data && r.data.message) || `Request failed (${r.status}).`;
}

export function hasRole(user, role) {
  return !!user && Array.isArray(user.roles) && user.roles.includes(role);
}

// ---- cart (stores only product ids + quantities + display labels) --------
const CART_KEY = "mp_cart_v1";
export const cart = {
  get() {
    try { return JSON.parse(localStorage.getItem(CART_KEY)) || []; } catch (_) { return []; }
  },
  save(items) {
    try { localStorage.setItem(CART_KEY, JSON.stringify(items)); } catch (_) { /* ignore */ }
    updateCartBadge();
  },
  add(product, qty) {
    const items = cart.get();
    if (items.length && items[0].seller_id !== product.seller_id) {
      return "Your cart has products from another store. All products in an order must come from one seller.";
    }
    const existing = items.find((i) => i.product_id === product.id);
    if (existing) existing.quantity += qty;
    else items.push({ product_id: product.id, quantity: qty, name: product.name,
                      seller_id: product.seller_id, store_name: product.store_name });
    cart.save(items);
    return null;
  },
  clear() { cart.save([]); },
};

function updateCartBadge() {
  const b = document.getElementById("cart-count");
  if (b) b.textContent = String(cart.get().reduce((s, i) => s + i.quantity, 0));
}

export async function renderNav() {
  const user = await currentUser();
  const nav = document.getElementById("nav");
  if (!nav) return user;
  const links = [el("a", { href: "/", class: "brand", text: "🛒 Marketplace" }), el("a", { href: "/", text: "Browse" })];
  if (user) {
    if (hasRole(user, "buyer")) {
      links.push(el("a", { href: "/cart" }, "Cart (", el("span", { id: "cart-count", text: "0" }), ")"));
      links.push(el("a", { href: "/orders", text: "My orders" }));
    }
    if (hasRole(user, "buyer") || hasRole(user, "seller")) links.push(el("a", { href: "/seller", text: "Seller" }));
    if (hasRole(user, "admin") || hasRole(user, "finance_officer")) {
      links.push(el("a", { href: "/api/docs", text: "API (Swagger)" }));
    }
    links.push(el("span", { class: "spacer" }));
    links.push(el("a", { href: "/account", text: user.full_name }));
    links.push(el("button", {
      class: "link", text: "Log out",
      onclick: async () => { await api("POST", "/api/auth/logout"); location.href = "/"; },
    }));
  } else {
    links.push(el("span", { class: "spacer" }));
    links.push(el("a", { href: "/login", text: "Log in" }));
    links.push(el("a", { href: "/register", class: "btn small", text: "Register" }));
  }
  nav.replaceChildren(...links);
  updateCartBadge();
  return user;
}

export function newIdempotencyKey() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function badge(status) {
  return el("span", { class: `badge ${status}`, text: status });
}

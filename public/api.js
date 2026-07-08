/**
 * api.js — thin fetch wrapper for the Eclipses Shop backend.
 * All requests are same-origin, credentials included so the httpOnly
 * session cookie is sent automatically.
 */

const Api = (() => {
  async function request(method, url, body) {
    const res = await fetch(url, {
      method,
      credentials: "include",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined
    });

    let data = null;
    try { data = await res.json(); } catch { /* no body */ }

    if (!res.ok) {
      const message = (data && data.error) || `Request failed (${res.status})`;
      throw new Error(message);
    }
    return data;
  }

  return {
    register: (username, password) => request("POST", "/api/register", { username, password }),
    login: (username, password) => request("POST", "/api/login", { username, password }),
    logout: () => request("POST", "/api/logout"),
    session: () => request("GET", "/api/session"),

    getCatalog: () => request("GET", "/api/catalog"),
    addCategory: (label) => request("POST", "/api/catalog/categories", { label }),
    deleteCategory: (id) => request("DELETE", `/api/catalog/categories/${encodeURIComponent(id)}`),
    addItem: (item) => request("POST", "/api/catalog/items", item),
    deleteItem: (id) => request("DELETE", `/api/catalog/items/${encodeURIComponent(id)}`),

    createOrder: (order) => request("POST", "/api/orders", order),
    getOrders: () => request("GET", "/api/orders"),
    getMyOrders: () => request("GET", "/api/my-orders"),
    clearOrders: () => request("DELETE", "/api/orders"),

    getOrderMessages: (orderId) => request("GET", `/api/orders/${encodeURIComponent(orderId)}/messages`),
    sendOrderMessage: (orderId, body) => request("POST", `/api/orders/${encodeURIComponent(orderId)}/messages`, { body })
  };
})();

function escapeHtml(str) {
  if (str === undefined || str === null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

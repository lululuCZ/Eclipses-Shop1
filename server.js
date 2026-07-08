/**
 * Eclipses Shop — backend server
 *
 * Real auth + real database, replacing the old localStorage-only version.
 *   - Passwords hashed with bcrypt (server-side, never touch the client).
 *   - Sessions are signed JWTs in httpOnly cookies (not readable/forgeable
 *     from devtools JS the way localStorage was).
 *   - Catalog + orders live in a SQLite file on disk, shared by everyone
 *     who uses the site — not per-browser anymore.
 *
 * Run:
 *   npm install
 *   npm start
 * Then open http://localhost:3000
 *
 * On first run, an admin account is created and its one-time password is
 * printed to this terminal (never sent to the browser).
 */

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.sqlite");

// JWT_SECRET should be set as a real environment variable in production
// (otherwise sessions reset whenever the server restarts). We generate a
// random one on boot as a safe default for local/dev use.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) {
  console.warn(
    "[warn] No JWT_SECRET env var set — using a random secret for this run only.\n" +
    "       Everyone will be logged out on restart. Set JWT_SECRET in production."
  );
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    category_id TEXT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    image TEXT,
    description TEXT,
    price REAL NOT NULL DEFAULT 0,
    robux INTEGER,
    lb INTEGER,
    gems INTEGER,
    huges INTEGER
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    method TEXT NOT NULL,
    items_summary TEXT NOT NULL,
    trade_username TEXT,
    delivery_type TEXT,
    notes TEXT
  );
`);

// ---- one-time setup: default categories + admin account ----
const categoryCount = db.prepare("SELECT COUNT(*) AS n FROM categories").get().n;
if (categoryCount === 0) {
  const insertCat = db.prepare("INSERT INTO categories (id, label, sort_order) VALUES (?, ?, ?)");
  insertCat.run("bases", "Bases", 0);
  insertCat.run("other", "Other", 1);
}

const adminExists = db.prepare("SELECT 1 FROM users WHERE username = 'admin'").get();
if (!adminExists) {
  const password = crypto.randomBytes(9).toString("base64url"); // random one-time password
  const hash = bcrypt.hashSync(password, 12);
  db.prepare(
    "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)"
  ).run("admin", hash, new Date().toISOString());

  console.log("\n==============================================");
  console.log(" Admin account created for this server.");
  console.log(" Username: admin");
  console.log(" Password: " + password);
  console.log(" (shown once — save it now; change it after logging in)");
  console.log("==============================================\n");
}

// ---------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

function signSession(user) {
  return jwt.sign(
    { sub: user.username, isAdmin: !!user.is_admin },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function setSessionCookie(res, token) {
  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function readSession(req) {
  const token = req.cookies.session;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: "Not logged in." });
  req.session = session;
  next();
}

function requireAdmin(req, res, next) {
  const session = readSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "Admin only." });
  req.session = session;
  next();
}

// ---------------- auth routes ----------------

app.post("/api/register", (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Username and password are required." });
  }
  const cleanUsername = username.trim();
  if (cleanUsername.length < 3 || cleanUsername.length > 32) {
    return res.status(400).json({ error: "Username must be 3-32 characters." });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
    return res.status(400).json({ error: "Username can only contain letters, numbers, underscores." });
  }
  if (cleanUsername.toLowerCase() === "admin") {
    return res.status(400).json({ error: "That username is reserved." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  const existing = db.prepare("SELECT 1 FROM users WHERE username = ?").get(cleanUsername);
  if (existing) {
    return res.status(409).json({ error: "That username is already taken." });
  }

  const hash = bcrypt.hashSync(password, 12);
  db.prepare(
    "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)"
  ).run(cleanUsername, hash, new Date().toISOString());

  const token = signSession({ username: cleanUsername, is_admin: 0 });
  setSessionCookie(res, token);
  res.json({ username: cleanUsername, isAdmin: false });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Username and password are required." });
  }

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password." });
  }

  const token = signSession(user);
  setSessionCookie(res, token);
  res.json({ username: user.username, isAdmin: !!user.is_admin });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

app.get("/api/session", (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: "Not logged in." });
  res.json({ username: session.sub, isAdmin: !!session.isAdmin });
});

// ---------------- catalog routes ----------------

function loadCatalog() {
  const categories = db.prepare("SELECT * FROM categories ORDER BY sort_order, label").all();
  const items = db.prepare("SELECT * FROM items").all();
  return categories.map(cat => ({
    id: cat.id,
    label: cat.label,
    items: items
      .filter(i => i.category_id === cat.id)
      .map(i => ({
        id: i.id,
        name: i.name,
        image: i.image || undefined,
        desc: i.description || "",
        price: i.price,
        robux: i.robux ?? undefined,
        lb: i.lb ?? undefined,
        gems: i.gems ?? undefined,
        huges: i.huges ?? undefined
      }))
  }));
}

app.get("/api/catalog", (req, res) => {
  res.json(loadCatalog());
});

function slugify(str) {
  return str.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || ("cat-" + Date.now());
}

app.post("/api/catalog/categories", requireAdmin, (req, res) => {
  const { label } = req.body || {};
  if (typeof label !== "string" || !label.trim()) {
    return res.status(400).json({ error: "Category name is required." });
  }
  const id = slugify(label);
  const maxOrder = db.prepare("SELECT COALESCE(MAX(sort_order), -1) AS m FROM categories").get().m;

  db.prepare("INSERT OR IGNORE INTO categories (id, label, sort_order) VALUES (?, ?, ?)")
    .run(id, label.trim().slice(0, 40), maxOrder + 1);

  res.json(loadCatalog());
});

app.delete("/api/catalog/categories/:id", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM categories WHERE id = ?").run(req.params.id);
  res.json(loadCatalog());
});

app.post("/api/catalog/items", requireAdmin, (req, res) => {
  const { categoryId, name, image, desc, price, robux, lb, gems, huges } = req.body || {};

  if (typeof categoryId !== "string" || typeof name !== "string" || !name.trim() || price === undefined) {
    return res.status(400).json({ error: "categoryId, name, and price are required." });
  }
  const category = db.prepare("SELECT 1 FROM categories WHERE id = ?").get(categoryId);
  if (!category) return res.status(400).json({ error: "Unknown category." });

  const id = "item-" + crypto.randomUUID();
  db.prepare(`
    INSERT INTO items (id, category_id, name, image, description, price, robux, lb, gems, huges)
    VALUES (@id, @categoryId, @name, @image, @desc, @price, @robux, @lb, @gems, @huges)
  `).run({
    id,
    categoryId,
    name: String(name).trim().slice(0, 60),
    image: image ? String(image).trim().slice(0, 500) : null,
    desc: desc ? String(desc).trim().slice(0, 200) : null,
    price: Number(price) || 0,
    robux: robux ? Number(robux) : null,
    lb: lb ? Number(lb) : null,
    gems: gems ? Number(gems) : null,
    huges: huges ? Number(huges) : null
  });

  res.json(loadCatalog());
});

app.delete("/api/catalog/items/:id", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM items WHERE id = ?").run(req.params.id);
  res.json(loadCatalog());
});

// ---------------- order routes ----------------

app.post("/api/orders", requireAuth, (req, res) => {
  const { method, items, tradeUsername, deliveryType, notes } = req.body || {};
  if (typeof method !== "string" || typeof items !== "string") {
    return res.status(400).json({ error: "method and items are required." });
  }

  const id = "ORD-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex");
  db.prepare(`
    INSERT INTO orders (id, username, created_at, method, items_summary, trade_username, delivery_type, notes)
    VALUES (@id, @username, @createdAt, @method, @items, @tradeUsername, @deliveryType, @notes)
  `).run({
    id,
    username: req.session.sub,
    createdAt: new Date().toISOString(),
    method: method.slice(0, 40),
    items: items.slice(0, 300),
    tradeUsername: tradeUsername ? String(tradeUsername).trim().slice(0, 60) : null,
    deliveryType: deliveryType ? String(deliveryType).slice(0, 60) : null,
    notes: notes ? String(notes).trim().slice(0, 500) : null
  });

  res.json({ ok: true, orderId: id });
});

app.get("/api/orders", requireAdmin, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders ORDER BY created_at DESC").all();
  res.json(orders.map(o => ({
    id: o.id,
    user: o.username,
    date: new Date(o.created_at).toLocaleString(),
    method: o.method,
    items: o.items_summary,
    tradeUsername: o.trade_username || undefined,
    deliveryType: o.delivery_type || undefined,
    notes: o.notes || undefined
  })));
});

app.delete("/api/orders", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM orders").run();
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Eclipses Shop server running at http://localhost:${PORT}`);
});

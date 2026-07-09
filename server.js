/**
 * Eclipses Shop — backend server (MongoDB Atlas edition)
 *
 * Real auth + real database:
 *   - Passwords hashed with bcrypt (server-side, never touch the client).
 *   - Sessions are signed JWTs in httpOnly cookies (not readable/forgeable
 *     from devtools JS the way localStorage was).
 *   - Catalog, orders, and chat messages live in MongoDB Atlas, shared by
 *     everyone who uses the site — not per-browser, not a local file.
 *
 * Run:
 *   npm install
 *   npm start
 * Then open http://localhost:3000
 *
 * Required env vars (see .env.example):
 *   MONGODB_URI   — your Atlas connection string
 *   JWT_SECRET    — long random string, keep stable across restarts
 *
 * On first run, an admin account is created and its one-time password is
 * printed to this terminal (never sent to the browser).
 */

const path = require("path");
const crypto = require("crypto");

try {
  require("dotenv").config();
} catch {
  console.warn("[warn] dotenv not installed — run `npm install dotenv` to auto-load .env, or export env vars manually.");
}

const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const { User, Category, Item, Order, OrderMessage, Review } = require("./models");

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error("[fatal] MONGODB_URI is not set. Add it to your .env file or host's env config.");
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) {
  console.warn(
    "[warn] No JWT_SECRET env var set — using a random secret for this run only.\n" +
    "       Everyone will be logged out on restart. Set JWT_SECRET in production."
  );
}

const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";
if (!DISCORD_WEBHOOK_URL) {
  console.warn("[warn] No DISCORD_WEBHOOK_URL env var set — order notifications are disabled.");
}

async function notifyDiscordNewOrder(order) {
  if (!DISCORD_WEBHOOK_URL) return;

  const fields = [
    { name: "Order ID", value: order.id, inline: true },
    { name: "Buyer", value: order.username, inline: true },
    { name: "Method", value: order.method, inline: true },
    { name: "Items", value: order.itemsSummary || "—" }
  ];
  if (order.tradeUsername) fields.push({ name: "Trade Username", value: order.tradeUsername, inline: true });
  if (order.tradeLink) fields.push({ name: "Trade Link", value: order.tradeLink, inline: true });
  if (order.deliveryType) fields.push({ name: "Delivery Preference", value: order.deliveryType, inline: true });
  if (order.notes) fields.push({ name: "Notes", value: order.notes });

  try {
    const res = await fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "🛒 New order — Eclipses Shop",
          color: 0xf2c879,
          fields,
          timestamp: new Date().toISOString()
        }]
      })
    });
    if (!res.ok) {
      console.error(`[discord] webhook responded ${res.status}: ${await res.text()}`);
    }
  } catch (err) {
    console.error("[discord] failed to send order notification:", err.message);
  }
}

async function main() {
  await mongoose.connect(MONGODB_URI, { dbName: process.env.DB_NAME || "eclipses_shop" });
  console.log("[db] connected to MongoDB Atlas");

  // ---- one-time setup: default categories + admin account ----
  const categoryCount = await Category.countDocuments();
  if (categoryCount === 0) {
    await Category.create([
      { id: "bases", label: "Bases", sortOrder: 0 },
      { id: "other", label: "Other", sortOrder: 1 }
    ]);
  }

  const adminExists = await User.findOne({ username: "admin" });
  if (!adminExists) {
    const password = crypto.randomBytes(9).toString("base64url");
    const passwordHash = bcrypt.hashSync(password, 12);
    await User.create({ username: "admin", passwordHash, isAdmin: true });

    console.log("\n==============================================");
    console.log(" Admin account created for this server.");
    console.log(" Username: admin");
    console.log(" Password: " + password);
    console.log(" (shown once — save it now; change it after logging in)");
    console.log("==============================================\n");
  }

  // ---------------------------------------------------------------

  const app = express();
  app.set("trust proxy", 1); // needed so req.ip is accurate behind Render/Railway/Fly's proxy
  app.use(express.json());
  app.use(cookieParser());
  app.use(express.static(path.join(__dirname, "public")));

  function signSession(user) {
    return jwt.sign(
      { sub: user.username, isAdmin: !!user.isAdmin },
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

  app.post("/api/register", async (req, res) => {
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

    const existing = await User.findOne({ username: cleanUsername });
    if (existing) {
      return res.status(409).json({ error: "That username is already taken." });
    }

    const passwordHash = bcrypt.hashSync(password, 12);
    await User.create({ username: cleanUsername, passwordHash, isAdmin: false });

    const token = signSession({ username: cleanUsername, isAdmin: false });
    setSessionCookie(res, token);
    res.json({ username: cleanUsername, isAdmin: false });
  });

  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Username and password are required." });
    }

    const user = await User.findOne({ username: username.trim() });
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const token = signSession(user);
    setSessionCookie(res, token);
    res.json({ username: user.username, isAdmin: !!user.isAdmin });
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

  async function loadCatalog() {
    const categories = await Category.find().sort({ sortOrder: 1, label: 1 });
    const items = await Item.find();
    return categories.map(cat => ({
      id: cat.id,
      label: cat.label,
      items: items
        .filter(i => i.categoryId === cat.id)
        .map(i => ({
          id: i.id,
          name: i.name,
          images: (i.images && i.images.length) ? i.images : (i.image ? [i.image] : []),
          desc: i.description || "",
          price: i.price,
          robux: i.robux ?? undefined,
          lb: i.lb ?? undefined,
          gems: i.gems ?? undefined,
          huges: i.huges ?? undefined
        }))
    }));
  }

  app.get("/api/catalog", async (req, res) => {
    res.json(await loadCatalog());
  });

  function slugify(str) {
    return str.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || ("cat-" + Date.now());
  }

  app.post("/api/catalog/categories", requireAdmin, async (req, res) => {
    const { label } = req.body || {};
    if (typeof label !== "string" || !label.trim()) {
      return res.status(400).json({ error: "Category name is required." });
    }
    const id = slugify(label);
    const maxOrderDoc = await Category.findOne().sort({ sortOrder: -1 });
    const maxOrder = maxOrderDoc ? maxOrderDoc.sortOrder : -1;

    const existing = await Category.findOne({ id });
    if (!existing) {
      await Category.create({ id, label: label.trim().slice(0, 40), sortOrder: maxOrder + 1 });
    }

    res.json(await loadCatalog());
  });

  app.delete("/api/catalog/categories/:id", requireAdmin, async (req, res) => {
    await Category.deleteOne({ id: req.params.id });
    await Item.deleteMany({ categoryId: req.params.id }); // mirrors old ON DELETE CASCADE
    res.json(await loadCatalog());
  });

  app.post("/api/catalog/items", requireAdmin, async (req, res) => {
    const { categoryId, name, image, images, desc, price, robux, lb, gems, huges } = req.body || {};

    if (typeof categoryId !== "string" || typeof name !== "string" || !name.trim() || price === undefined) {
      return res.status(400).json({ error: "categoryId, name, and price are required." });
    }
    const category = await Category.findOne({ id: categoryId });
    if (!category) return res.status(400).json({ error: "Unknown category." });

    // Accept either a single legacy `image` string or an `images` array;
    // normalize to a clean array of trimmed, capped URLs.
    let cleanImages = [];
    if (Array.isArray(images)) {
      cleanImages = images
        .filter(url => typeof url === "string" && url.trim())
        .map(url => url.trim().slice(0, 500))
        .slice(0, 10);
    } else if (image && typeof image === "string" && image.trim()) {
      cleanImages = [image.trim().slice(0, 500)];
    }

    const id = "item-" + crypto.randomUUID();
    await Item.create({
      id,
      categoryId,
      name: String(name).trim().slice(0, 60),
      images: cleanImages.length ? cleanImages : undefined,
      description: desc ? String(desc).trim().slice(0, 200) : undefined,
      price: Number(price) || 0,
      robux: robux ? Number(robux) : undefined,
      lb: lb ? Number(lb) : undefined,
      gems: gems ? Number(gems) : undefined,
      huges: huges ? Number(huges) : undefined
    });

    res.json(await loadCatalog());
  });

  app.delete("/api/catalog/items/:id", requireAdmin, async (req, res) => {
    await Item.deleteOne({ id: req.params.id });
    res.json(await loadCatalog());
  });

  // ---------------- order routes ----------------

  function mapOrder(o) {
    return {
      id: o.id,
      user: o.username,
      date: new Date(o.createdAt).toLocaleString(),
      method: o.method,
      items: o.itemsSummary,
      tradeUsername: o.tradeUsername || undefined,
      tradeLink: o.tradeLink || undefined,
      deliveryType: o.deliveryType || undefined,
      notes: o.notes || undefined
    };
  }

  // Returns the order doc only if the requesting session is allowed to see it
  // (its own owner, or an admin) — otherwise null.
  async function getAccessibleOrder(orderId, session) {
    const order = await Order.findOne({ id: orderId });
    if (!order) return null;
    if (!session.isAdmin && order.username !== session.sub) return null;
    return order;
  }

  app.get("/api/my-orders", requireAuth, async (req, res) => {
    const orders = await Order.find({ username: req.session.sub }).sort({ createdAt: -1 });
    res.json(orders.map(mapOrder));
  });

  app.get("/api/orders/:id/messages", requireAuth, async (req, res) => {
    const order = await getAccessibleOrder(req.params.id, req.session);
    if (!order) return res.status(404).json({ error: "Order not found." });

    const messages = await OrderMessage.find({ orderId: req.params.id }).sort({ createdAt: 1 });
    res.json(messages.map(m => ({
      id: m.id,
      sender: m.sender,
      isAdmin: !!m.isAdmin,
      body: m.body,
      createdAt: m.createdAt
    })));
  });

  app.post("/api/orders/:id/messages", requireAuth, async (req, res) => {
    const order = await getAccessibleOrder(req.params.id, req.session);
    if (!order) return res.status(404).json({ error: "Order not found." });

    const { body } = req.body || {};
    if (typeof body !== "string" || !body.trim()) {
      return res.status(400).json({ error: "Message cannot be empty." });
    }

    const record = {
      id: "MSG-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex"),
      orderId: req.params.id,
      sender: req.session.sub,
      isAdmin: !!req.session.isAdmin,
      body: body.trim().slice(0, 1000)
    };

    const saved = await OrderMessage.create(record);

    res.json({
      id: saved.id,
      sender: saved.sender,
      isAdmin: !!saved.isAdmin,
      body: saved.body,
      createdAt: saved.createdAt
    });
  });

  app.post("/api/orders", requireAuth, async (req, res) => {
    const { method, items, tradeUsername, tradeLink, deliveryType, notes } = req.body || {};
    if (typeof method !== "string" || typeof items !== "string") {
      return res.status(400).json({ error: "method and items are required." });
    }

    const id = "ORD-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex");
    const record = {
      id,
      username: req.session.sub,
      method: method.slice(0, 40),
      itemsSummary: items.slice(0, 300),
      tradeUsername: tradeUsername ? String(tradeUsername).trim().slice(0, 60) : undefined,
      tradeLink: tradeLink ? String(tradeLink).trim().slice(0, 300) : undefined,
      deliveryType: deliveryType ? String(deliveryType).slice(0, 60) : undefined,
      notes: notes ? String(notes).trim().slice(0, 500) : undefined
    };

    await Order.create(record);

    res.json({ ok: true, orderId: id });

    // Fire-and-forget: don't make the buyer wait on Discord's response.
    notifyDiscordNewOrder(record);
  });

  app.get("/api/orders", requireAdmin, async (req, res) => {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders.map(mapOrder));
  });

  app.delete("/api/orders", requireAdmin, async (req, res) => {
    await Order.deleteMany({});
    await OrderMessage.deleteMany({});
    res.json({ ok: true });
  });

  // ---------------- review routes ----------------
  // Reading reviews is public; posting one requires a logged-in account so
  // the review is tied to a real username instead of arbitrary free text.

  // Simple per-user rate limit so the endpoint can't be spammed.
  // Not persisted across restarts; good enough to deter casual abuse.
  const reviewSubmitTimestamps = new Map(); // username -> last submit time (ms)
  const REVIEW_COOLDOWN_MS = 60 * 1000;

  app.get("/api/reviews", async (req, res) => {
    const reviews = await Review.find().sort({ createdAt: -1 }).limit(200);
    res.json(reviews.map(r => ({
      id: r.id,
      name: r.name,
      stars: r.stars,
      text: r.text,
      createdAt: r.createdAt
    })));
  });

  app.post("/api/reviews", requireAuth, async (req, res) => {
    const username = req.session.sub;
    const lastSubmit = reviewSubmitTimestamps.get(username);
    if (lastSubmit && Date.now() - lastSubmit < REVIEW_COOLDOWN_MS) {
      return res.status(429).json({ error: "Please wait a moment before submitting another review." });
    }

    const { stars, text } = req.body || {};
    if (typeof text !== "string" || !text.trim()) {
      return res.status(400).json({ error: "Review text is required." });
    }
    const starsNum = Number(stars);
    if (!Number.isInteger(starsNum) || starsNum < 1 || starsNum > 5) {
      return res.status(400).json({ error: "Stars must be a number 1-5." });
    }

    const id = "REV-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex");
    await Review.create({
      id,
      name: username,
      stars: starsNum,
      text: text.trim().slice(0, 500)
    });

    reviewSubmitTimestamps.set(username, Date.now());
    res.json({ ok: true });
  });

  app.delete("/api/reviews/:id", requireAdmin, async (req, res) => {
    await Review.deleteOne({ id: req.params.id });
    res.json({ ok: true });
  });

  app.listen(PORT, () => {
    console.log(`Eclipses Shop server running at http://localhost:${PORT}`);
  });
}

main().catch(err => {
  console.error("[fatal] failed to start server:", err);
  process.exit(1);
});

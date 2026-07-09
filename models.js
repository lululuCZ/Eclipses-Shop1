/**
 * models.js — Mongoose schemas for Eclipses Shop.
 * Replaces the old SQLite tables (users, categories, items, orders, order_messages).
 */

const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const CategorySchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true }, // slug, e.g. "bases"
  label: { type: String, required: true },
  sortOrder: { type: Number, default: 0 }
});

const ItemSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true }, // "item-<uuid>"
  categoryId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  image: { type: String },
  description: { type: String },
  price: { type: Number, default: 0 },
  robux: { type: Number },
  lb: { type: Number },
  gems: { type: Number },
  huges: { type: Number }
});

const OrderSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true }, // "ORD-<ts>-<hex>"
  username: { type: String, required: true, index: true },
  createdAt: { type: Date, default: Date.now },
  method: { type: String, required: true },
  itemsSummary: { type: String, required: true },
  tradeUsername: { type: String },
  tradeLink: { type: String },
  deliveryType: { type: String },
  notes: { type: String }
});

const OrderMessageSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true }, // "MSG-<ts>-<hex>"
  orderId: { type: String, required: true, index: true },
  sender: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  body: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);
const Category = mongoose.model("Category", CategorySchema);
const Item = mongoose.model("Item", ItemSchema);
const Order = mongoose.model("Order", OrderSchema);
const OrderMessage = mongoose.model("OrderMessage", OrderMessageSchema);

module.exports = { User, Category, Item, Order, OrderMessage };

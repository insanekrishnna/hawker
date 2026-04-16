import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.db");

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true,
  })
);

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Admin','Hawker','Citizen','Enforcement','UrbanDevelopment','Revenue')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/auth/signup", (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = db
    .prepare("SELECT id FROM users WHERE email = ?")
    .get(normalizedEmail);
  if (existing) {
    return res.status(409).json({ message: "Email already registered" });
  }

  const password_hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare(
    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)"
  );
  const info = stmt.run(name, normalizedEmail, password_hash, role);
  const user = db
    .prepare("SELECT id, name, email, role FROM users WHERE id = ?")
    .get(info.lastInsertRowid);

  const token = signToken(user);
  res.json({ token, user });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password || !role) {
    return res
      .status(400)
      .json({ message: "Email, password, and role are required" });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const user = db
    .prepare(
      "SELECT id, name, email, role, password_hash FROM users WHERE email = ?"
    )
    .get(normalizedEmail);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  if (user.role !== role) {
    return res.status(403).json({
      message: `Role mismatch. Your account is registered as ${user.role}.`,
    });
  }

  const token = signToken(user);
  const safeUser = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };
  res.json({ token, user: safeUser });
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  const user = db
    .prepare("SELECT id, name, email, role FROM users WHERE id = ?")
    .get(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ user });
});

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ message: "Server error" });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  console.error("Missing DATABASE_URL or SESSION_SECRET. Copy .env.example to .env and configure it.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false
});

app.use(helmet());
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.json());
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 2
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
function page(title, body, message = "") {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
  <style>
  body{font-family:Arial,sans-serif;background:#f2f5fb;margin:0;color:#182235}
  main{max-width:480px;margin:6vh auto;padding:24px;background:white;border-radius:14px;box-shadow:0 8px 28px #14213d18}
  h1{font-size:1.6rem}label{display:block;margin-top:14px;font-weight:600}
  input{box-sizing:border-box;width:100%;padding:12px;margin-top:6px;border:1px solid #cbd5e1;border-radius:8px}
  button,.button{display:inline-block;margin-top:18px;padding:12px 16px;border:0;border-radius:8px;background:#2563eb;color:white;font-weight:bold;text-decoration:none;cursor:pointer}
  .links{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px}.msg{padding:10px;background:#eff6ff;border-radius:8px}
  .muted{color:#64748b;font-size:.92rem}form{margin:0}
  </style></head><body><main><h1>${escapeHtml(title)}</h1>
  ${message ? `<p class="msg">${escapeHtml(message)}</p>` : ""}${body}</main></body></html>`;
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      email VARCHAR(254) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      reset_token_hash TEXT,
      reset_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}
function authLinks() {
  return `<div class="links"><a href="/register">Create account</a><a href="/forgot-password">Forgot password?</a></div>`;
}
app.get("/", (req, res) => {
  res.send(page("Task 4 Authentication", `<p>Authentication and database integration starter project.</p>
  <div class="links"><a class="button" href="/register">Sign up</a><a class="button" href="/login">Log in</a></div>`));
});

app.get("/register", (req, res) => res.send(page("Create account", `
  <form method="post" action="/register">
  <label>Name</label><input name="name" required maxlength="80" autocomplete="name">
  <label>Email</label><input name="email" type="email" required maxlength="254" autocomplete="email">
  <label>Password (minimum 8 characters)</label><input name="password" type="password" required minlength="8" autocomplete="new-password">
  <button type="submit">Create account</button></form>${authLinks()}`)));

app.post("/register", authLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!name || name.length > 80 || !validEmail(email) || password.length < 8 || password.length > 128) {
      return res.status(400).send(page("Registration error", "Please enter a valid name and email, and a password of 8–128 characters.", "Check your details."));
    }
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING id",
      [name, email, hash]
    );
    if (!result.rowCount) return res.status(409).send(page("Registration error", "An account with this email already exists.", "Please log in instead."));
    req.session.userId = result.rows[0].id;
    req.session.userName = name;
    res.redirect("/dashboard");
  } catch (err) { next(err); }
});

app.get("/login", (req, res) => res.send(page("Log in", `
  <form method="post" action="/login">
  <label>Email</label><input name="email" type="email" required autocomplete="email">
  <label>Password</label><input name="password" type="password" required autocomplete="current-password">
  <button type="submit">Log in</button></form>${authLinks()}`)));

app.post("/login", authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const result = await pool.query("SELECT id,name,password_hash FROM users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).send(page("Login failed", "Email or password is incorrect.", "Please try again."));
    }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.userName = user.name;
      req.session.save(err2 => err2 ? next(err2) : res.redirect("/dashboard"));
    });
  } catch (err) { next(err); }
});

app.get("/dashboard", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT id,name,email,created_at FROM users WHERE id=$1", [req.session.userId]);
    if (!result.rowCount) { req.session.destroy(() => res.redirect("/login")); return; }
    const user = result.rows[0];
    res.send(page("Your dashboard", `<p>Welcome, <strong>${escapeHtml(user.name)}</strong>!</p>
      <p>Email: ${escapeHtml(user.email)}</p><p class="muted">Account ID: ${user.id}</p>
      <form method="post" action="/logout"><button type="submit">Log out</button></form>
      <p><a href="/forgot-password">Reset password</a></p>`, "You are logged in. This is a protected route."));
  } catch (err) { next(err); }
});

app.post("/logout", requireAuth, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

async function sendResetEmail(email, resetUrl) {
  console.log("SMTP environment diagnostic:", {
  hostPresent: Boolean(process.env.SMTP_HOST?.trim()),
  userPresent: Boolean(process.env.SMTP_USER?.trim()),
  passPresent: Boolean(process.env.SMTP_PASS),
  fromPresent: Boolean(process.env.EMAIL_FROM?.trim()),
  nodeEnv: process.env.NODE_ENV || "not set"
});
  console.log("SMTP configuration check:", {
  host: Boolean(process.env.SMTP_HOST),
  user: Boolean(process.env.SMTP_USER),
  pass: Boolean(process.env.SMTP_PASS),
  from: Boolean(process.env.EMAIL_FROM)
});
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.EMAIL_FROM) {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT || 587) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({
      from: process.env.EMAIL_FROM, to: email,
      subject: "Password reset request",
      text: `Use this link to reset your password. It expires in 15 minutes: ${resetUrl}`
    });
  } else {
    // Development only: do not expose reset links to public users in production.
    console.log(`[DEV ONLY] Password reset link for ${email}: ${resetUrl}`);
  }
}
app.get("/forgot-password", (req, res) => res.send(page("Forgot password", `
  <p>Enter your account email. If it exists, password reset instructions will be prepared.</p>
  <form method="post" action="/forgot-password"><label>Email</label>
  <input name="email" type="email" required autocomplete="email"><button type="submit">Request reset</button></form>
  <div class="links"><a href="/login">Back to login</a></div>`)));

app.post("/forgot-password", authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (validEmail(email)) {
      const result = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
      if (result.rowCount) {
        const token = crypto.randomBytes(32).toString("hex");
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
        await pool.query("UPDATE users SET reset_token_hash=$1, reset_expires_at=NOW() + INTERVAL '15 minutes' WHERE email=$2", [tokenHash, email]);
        const resetUrl = `${req.protocol}://${req.get("host")}/reset-password/${token}`;
        await sendResetEmail(email, resetUrl);
      }
    }
    res.send(page("Check your email", "If an account with that email exists, reset instructions will be available. In local development, check the server terminal for the reset link."));
  } catch (err) { next(err); }
});

app.get("/reset-password/:token", (req, res) => res.send(page("Choose a new password", `
  <form method="post" action="/reset-password/${encodeURIComponent(req.params.token)}">
  <label>New password (minimum 8 characters)</label><input name="password" type="password" required minlength="8" maxlength="128" autocomplete="new-password">
  <button type="submit">Update password</button></form>`)));

app.post("/reset-password/:token", authLimiter, async (req, res, next) => {
  try {
    const password = String(req.body.password || "");
    if (password.length < 8 || password.length > 128) return res.status(400).send(page("Invalid password", "Password must be 8–128 characters."));
    const tokenHash = crypto.createHash("sha256").update(String(req.params.token)).digest("hex");
    const result = await pool.query("SELECT id FROM users WHERE reset_token_hash=$1 AND reset_expires_at > NOW()", [tokenHash]);
    if (!result.rowCount) return res.status(400).send(page("Reset link invalid", "This link is invalid or has expired. Request a new one."));
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query("UPDATE users SET password_hash=$1, reset_token_hash=NULL, reset_expires_at=NULL WHERE id=$2", [passwordHash, result.rows[0].id]);
    res.send(page("Password updated", "Your password was changed successfully.", "You can now log in with your new password."));
  } catch (err) { next(err); }
});

app.get("/health", (req, res) => res.json({ success: true, message: "Authentication app is running" }));
app.use((req, res) => res.status(404).send(page("Page not found", "The requested page does not exist.")));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).send(page("Server error", "Something went wrong. Please try again later."));
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`Task 4 app running on port ${PORT}`));
}).catch(err => {
  console.error("Database initialization failed:", err.message);
  process.exit(1);
});

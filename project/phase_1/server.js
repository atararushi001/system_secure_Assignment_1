require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const db = require("./config/db");

const app = express();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ✅ FIXED SESSION (VERY IMPORTANT)
app.use(session({
  secret: "secretkey",
  resave: false,
  saveUninitialized: false, // 🔥 IMPORTANT FIX
  cookie: {
    secure: false
  }
}));

// ================= RATE LIMIT =================
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: "Too many login attempts. Try later."
});

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (email,password) VALUES (?,?)",
    [email, hash],
    err => {
      if (err) return res.send("User already exists");
      res.redirect("/login.html");
    }
  );
});

// ================= LOGIN =================
app.post("/login", limiter, async (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, r) => {
    if (!r.length) return res.send("Invalid credentials");

    const u = r[0];

    // 🔒 ACCOUNT LOCK CHECK
    if (u.lock_until && u.lock_until > Date.now())
      return res.send("Account locked. Try later.");

    const ok = await bcrypt.compare(password, u.password);

    if (!ok) {
      let attempts = u.failed_attempts + 1;
      let lock = null;

      if (attempts >= 5)
        lock = Date.now() + 15 * 60 * 1000;

      db.query(
        "UPDATE users SET failed_attempts=?, lock_until=? WHERE id=?",
        [attempts, lock, u.id]
      );

      return res.send("Invalid credentials");
    }

    // reset attempts
    db.query(
      "UPDATE users SET failed_attempts=0, lock_until=NULL WHERE id=?",
      [u.id]
    );

    // ✅ SAVE SESSION
    req.session.email = email;
    console.log("SESSION SET:", req.session.email);

    // 🔁 FLOW CONTROL
    if (!u.twofa_enabled)
      return res.redirect("/setup2fa.html");

    return res.redirect("/otp.html");
  });
});

// ================= 2FA SETUP =================
app.post("/2fa/setup", (req, res) => {
  const email = req.session.email;

  if (!email) return res.send("Session expired. Login again.");

  const secret = speakeasy.generateSecret({ length: 20 });

  db.query(
    "UPDATE users SET twofa_secret=? WHERE email=?",
    [secret.base32, email],
    () => {
      QRCode.toDataURL(secret.otpauth_url, (err, qr) => {
        res.send(`
          <h2>Scan QR in Google Authenticator</h2>
          <img src="${qr}" />
          <br><br>
          <a href="/verify2fa.html">Next → Verify OTP</a>
        `);
      });
    }
  );
});

// ================= VERIFY 2FA =================
app.post("/2fa/verify", (req, res) => {
  const email = req.session.email;
  const { token } = req.body;

  if (!email) return res.send("Session expired. Login again.");

  db.query("SELECT * FROM users WHERE email=?", [email], (err, r) => {
    const u = r[0];

    const verified = speakeasy.totp.verify({
      secret: u.twofa_secret,
      encoding: "base32",
      token: token.trim(),
      window: 2
    });

    if (!verified) return res.send("Invalid OTP");

    db.query(
      "UPDATE users SET twofa_enabled=1 WHERE email=?",
      [email]
    );

    res.send(`
      <h2>2FA Enabled Successfully ✅</h2>
      <a href="/login.html">Login Again</a>
    `);
  });
});

// ================= OTP LOGIN =================
app.post("/2fa/login", (req, res) => {
  const email = req.session.email;

  if (!email) {
    return res.send("Session expired. Please login again.");
  }

  let { token } = req.body;
  token = token.trim();

  db.query("SELECT * FROM users WHERE email=?", [email], (err, r) => {
    const u = r[0];

    console.log("EMAIL:", email);
    console.log("TOKEN:", token);

    // 🔁 REPLAY PROTECTION
    if (u.last_otp === token) {
      return res.send("Replay attack detected ❌");
    }

    const verified = speakeasy.totp.verify({
      secret: u.twofa_secret,
      encoding: "base32",
      token,
      window: 2
    });

    if (!verified) return res.send("Invalid OTP");

    // store last OTP
    db.query(
      "UPDATE users SET last_otp=?, last_otp_time=? WHERE id=?",
      [token, Date.now(), u.id]
    );

    res.send("<h2>Login Successful 🎉</h2>");
  });
});

app.listen(5000, () => console.log("Server running on port 5000"));
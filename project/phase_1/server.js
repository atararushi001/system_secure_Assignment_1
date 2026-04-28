require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");

const db = require("./config/db");

const app = express();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set("trust proxy", 1);

// ================= RATE LIMIT =================
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  handler: (req, res) => {
    console.log("🚫 RATE LIMIT TRIGGERED:", req.ip);
    return res.send("Invalid credentials"); // ✅ IMPORTANT
  }
});

app.use("/login", limiter);

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (email, password) VALUES (?, ?)",
    [email, hash],
    (err) => {
      if (err) return res.send("User already exists");
      res.redirect("/login.html");
    }
  );
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const now = Date.now();

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, r) => {
    if (err) return res.send("Invalid credentials");

    if (r.length === 0) {
      return res.send("Invalid credentials");
    }

    const user = r[0];

    // 🔒 CHECK LOCK
    if (user.lock_until && now < user.lock_until) {
      console.log("🔒 Account locked:", email);
      return res.send("Invalid credentials"); // ✅ IMPORTANT
    }

    // 🔓 RESET IF LOCK EXPIRED
    if (user.lock_until && now >= user.lock_until) {
      await new Promise(resolve =>
        db.query(
          "UPDATE users SET failed_attempts=0, lock_until=NULL WHERE id=?",
          [user.id],
          resolve
        )
      );
      user.failed_attempts = 0;
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      const attempts = user.failed_attempts + 1;

      // 🔥 LOCK AFTER 3 ATTEMPTS
      if (attempts >= 3) {
        const lockUntil = now + 5 * 60 * 1000;

        await new Promise(resolve =>
          db.query(
            "UPDATE users SET failed_attempts=?, lock_until=? WHERE id=?",
            [attempts, lockUntil, user.id],
            resolve
          )
        );

        console.log("🔒 Account locked:", email);
        return res.send("Invalid credentials"); // ✅ IMPORTANT
      }

      await new Promise(resolve =>
        db.query(
          "UPDATE users SET failed_attempts=? WHERE id=?",
          [attempts, user.id],
          resolve
        )
      );

      return res.send("Invalid credentials"); // ✅ IMPORTANT
    }

    // ✅ SUCCESS
    await new Promise(resolve =>
      db.query(
        "UPDATE users SET failed_attempts=0, lock_until=NULL WHERE id=?",
        [user.id],
        resolve
      )
    );

    console.log("✅ Login success:", email);
    res.send("Login successful");
  });
});

// ================= SERVER =================
app.listen(5000, () => {
  console.log("🚀 Server running on http://localhost:5000");
});
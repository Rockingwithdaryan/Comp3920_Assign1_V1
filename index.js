require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const CryptoJS = require("crypto-js");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ─── STATIC / PUBLIC FOLDER ──────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ─── MYSQL CONNECTION ────────────────────────────────────────
const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

db.connect((err) => {
  if (err) {
    console.error("MySQL connection failed:", err);
  } else {
    console.log("✓ Connected to MySQL");
    // Create the users table if it does not already exist
    db.query(
      `CREATE TABLE IF NOT EXISTS users (
         id INT AUTO_INCREMENT PRIMARY KEY,
         username VARCHAR(100) NOT NULL UNIQUE,
         password VARCHAR(255) NOT NULL
       )`,
      (err) => {
        if (err) console.error("Error creating users table:", err);
        else console.log("✓ Users table ready");
      }
    );
  }
});

// ─── MONGODB + SESSION SETUP ─────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✓ Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection failed:", err));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongooseConnection: mongoose.connection,
      collectionName: "sessions",
      // Session expires after 1 hour (60 min × 60 sec × 1000 ms)
      ttl: 60 * 60,
    }),
    cookie: {
      // Cookie also expires after 1 hour
      maxAge: 60 * 60 * 1000,
    },
  })
);

// ─── HELPER: encrypt / decrypt a value for the client cookie ─
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

function encryptValue(value) {
  return CryptoJS.AES.encrypt(value, ENCRYPTION_KEY).toString();
}

function decryptValue(ciphertext) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
}

// ─── HELPER: send an HTML page (no template engine – keeps it simple) ───
// NOTE (V1 – UNSAFE): username is inserted directly into HTML with NO escaping.
//       This is intentionally vulnerable to HTML / XSS injection.
function renderHome(res, username) {
  if (username) {
    // ⚠️  UNSAFE – username rendered raw (HTML injection point)
    res.send(`
      <!DOCTYPE html><html><head><title>Home</title><link rel="stylesheet" href="/style.css"></head>
      <body>
        <h1>Welcome, ${username}!</h1>
        <a href="/members">Members Area</a><br>
        <a href="/logout">Sign Out</a>
      </body></html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html><html><head><title>Home</title><link rel="stylesheet" href="/style.css"></head>
      <body>
        <h1>Welcome</h1>
        <a href="/signup">Sign Up</a><br>
        <a href="/login">Log In</a>
      </body></html>
    `);
  }
}

// ─── GET / ────────────────────────────────────────────────────
app.get("/", (req, res) => {
  if (req.session && req.session.username) {
    renderHome(res, req.session.username);
  } else {
    renderHome(res, null);
  }
});

// ─── GET /signup ──────────────────────────────────────────────
app.get("/signup", (req, res) => {
  const error = req.query.error || "";
  let errorMsg = "";
  if (error === "username") errorMsg = '<p style="color:red">Please provide a username.</p>';
  if (error === "password") errorMsg = '<p style="color:red">Please provide a password.</p>';

  res.send(`
    <!DOCTYPE html><html><head><title>Sign Up</title><link rel="stylesheet" href="/style.css"></head>
    <body>
      <h1>Sign Up</h1>
      ${errorMsg}
      <form action="/signup" method="POST">
        <label>Username: <input type="text" name="username"></label><br><br>
        <label>Password: <input type="password" name="password"></label><br><br>
        <button type="submit">Sign Up</button>
      </form>
    </body></html>
  `);
});

// ─── POST /signup ─────────────────────────────────────────────
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  // Basic empty-check validation
  if (!username || username.trim() === "") return res.redirect("/signup?error=username");
  if (!password || password.trim() === "") return res.redirect("/signup?error=password");

  // Hash the password with bcrypt
  const hashedPassword = await bcrypt.hash(password, 10);

  // ⚠️  UNSAFE – username is concatenated directly into the SQL string.
  //     This is the intentional SQL injection vulnerability for Version 1.
  const query = `INSERT INTO users (username, password) VALUES ('${username}', '${hashedPassword}')`;

  db.query(query, (err) => {
    if (err) {
      console.error("Signup DB error:", err);
      return res.send(`
        <!DOCTYPE html><html><head><title>Error</title></head>
        <body><h1>Sign Up Error</h1><p>${err.message}</p><a href="/signup">Try again</a></body></html>
      `);
    }

    // Create session and store encrypted username cookie
    req.session.username = username;
    res.cookie("encrypted_user", encryptValue(username));
    res.redirect("/members");
  });
});

// ─── GET /login ───────────────────────────────────────────────
app.get("/login", (req, res) => {
  const error = req.query.error || "";
  let errorMsg = "";
  if (error === "credentials") errorMsg = '<p style="color:red">User and password not found.</p>';

  res.send(`
    <!DOCTYPE html><html><head><title>Log In</title><link rel="stylesheet" href="/style.css"></head>
    <body>
      <h1>Log In</h1>
      ${errorMsg}
      <form action="/login" method="POST">
        <label>Username: <input type="text" name="username"></label><br><br>
        <label>Password: <input type="password" name="password"></label><br><br>
        <button type="submit">Log In</button>
      </form>
    </body></html>
  `);
});

// ─── POST /login ──────────────────────────────────────────────
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // ⚠️  UNSAFE – username is concatenated directly into the SQL string.
  const query = `SELECT * FROM users WHERE username = '${username}'`;

  db.query(query, async (err, results) => {
    if (err) {
      console.error("Login DB error:", err);
      return res.redirect("/login?error=credentials");
    }

    if (results.length === 0) return res.redirect("/login?error=credentials");

    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) return res.redirect("/login?error=credentials");

    // Valid login – create session
    req.session.username = user.username;
    res.cookie("encrypted_user", encryptValue(user.username));
    res.redirect("/members");
  });
});

// ─── GET /members ─────────────────────────────────────────────
app.get("/members", (req, res) => {
  // Guard – redirect if no valid session
  if (!req.session || !req.session.username) {
    return res.redirect("/");
  }

  // Pick a random image (1, 2, or 3) from /public/images/
  const imgNum = Math.floor(Math.random() * 3) + 1;
  const imgSrc = `/images/img${imgNum}.jpg`;

  // ⚠️  UNSAFE – username rendered raw (HTML injection point)
  res.send(`
    <!DOCTYPE html><html><head><title>Members</title><link rel="stylesheet" href="/style.css"></head>
    <body>
      <h1>Hello, ${req.session.username}!</h1>
      <img src="${imgSrc}" alt="Random Image" style="max-width:400px;"><br><br>
      <a href="/logout">Sign Out</a>
    </body></html>
  `);
});

// ─── GET /logout ──────────────────────────────────────────────
app.get("/logout", (req, res) => {
  // Destroy the session (removes it from MongoDB)
  req.session.destroy((err) => {
    if (err) console.error("Session destroy error:", err);
  });
  // Clear the encrypted cookie
  res.clearCookie("encrypted_user");
  res.redirect("/");
});

// ─── 404 CATCH-ALL (must be LAST route) ──────────────────────
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html><html><head><title>404 – Page Not Found</title><link rel="stylesheet" href="/style.css"></head>
    <body>
      <h1>404 – Page Not Found</h1>
      <p>The page you are looking for does not exist.</p>
      <a href="/">Go Home</a>
    </body></html>
  `);
});

// ─── START SERVER ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 V1 (UNSAFE) server running on port ${PORT}\n`);
});

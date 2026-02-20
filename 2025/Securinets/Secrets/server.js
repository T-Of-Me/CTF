require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const cookieParser = require("cookie-parser");
const csrf = require('@dr.pogodin/csurf');
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/user");
const adminRoutes = require("./routes/admin");
const logRoutes = require("./routes/log");

const app = express();

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.use((req, res, next) => {
  try {
    res.locals.csrfToken = req.csrfToken();
  } catch (err) {
    res.locals.csrfToken = null;
  }
  next();
});

// Set view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Endpoint to fetch CSRF token for AJAX
app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Pages
app.get("/register", (req, res) => res.render("register"));
app.get("/", (req, res) => res.render("login"));
app.get("/login", (req, res) => res.render("login"));

// Routes
app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/admin", adminRoutes);

app.use("/msg", require("./routes/msgs"));

app.use("/log", logRoutes);

app.use("/report", require("./routes/report"));

app.use("/secrets", require("./routes/secrets"));



app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    if (req.accepts("html")) {
      return res
        .status(403)
        .send("<h1>403 - Invalid CSRF Token</h1><p>Please refresh the page and try again.</p>");
    } else {
      return res.status(403).json({ error: "Invalid CSRF token" });
    }
  }
  next(err);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);

// A simple Express.js application to demonstrate user registration, login,
// session handling, and safe rendering of user-controlled data.
//
// === WARNING: FOR CTF (CAPTURE THE FLAG) USE ONLY ===
// This code stores passwords in plaintext. This is a severe security vulnerability
// and should NEVER be used in a production or real-world application.
//
// This is done to fulfill the user's request for a CTF scenario.

// 1. Import necessary libraries
// Note: You will need to run `npm install express express-session` to use this code.
// bcrypt has been removed as per the CTF request.
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const FLAG = process.env.FLAG || "justCTF{example_flag}"
const SECRET = crypto.randomBytes(24).toString('hex');

// 2. Middleware to parse request bodies (for form data)
app.use(express.urlencoded({ extended: true }));

// 3. Configure session middleware
app.use(session({
  secret: SECRET, 
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// 4. In-memory user data store (simulating a database)
// In a real application, you would use a database like MongoDB or PostgreSQL.
// For this CTF scenario, passwords are stored in plaintext.
const users = {}; // Stores { username: { password, userThemeConfig, isAdmin } }

// 5. A simple function to safely escape HTML to prevent XSS attacks.
const escapeHtml = (unsafe) => {
  if (typeof unsafe !== 'string') return unsafe;
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// 6. A function to recursively merge objects
const deepMerge = (target, source) => {
  for (const key in source) {
    if (source[key] instanceof Object && key in target) {
      Object.assign(source[key], deepMerge(target[key], source[key]));
    }
  }
  Object.assign(target || {}, source);
  return target;
};

// 7. A function to parse a query string with dot-notation keys.
const parseQueryParams = (queryString) => {
  if (typeof queryString !== 'string') {
    return {};
  }
  const cleanString = queryString.startsWith('?') ? queryString.substring(1) : queryString;
  const params = new URLSearchParams(cleanString);
  const result = {};
  for (const [key, value] of params.entries()) {
    const path = key.split('.');
    let current = result;
    for (let i = 0; i < path.length; i++) {
      let part = path[i];
      // Protect against Prototype Pollution vulnerability
      if(['__proto__', 'prototype', 'constructor'].includes(part)){
        part = '__unsafe$' + part;
      }
      if (i === path.length - 1) {
        current[part] = value;
      } else {
        if (!current[part] || typeof current[part] !== 'object') {
          current[part] = {};
        }
        current = current[part];
      }
    }
  }
  return result;
};


// 8. Authentication Middleware
// This function checks if a user is logged in before allowing access to a route.
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    next(); // User is authenticated, proceed to the next middleware/route handler
  } else {
    res.redirect('/login'); // User is not authenticated, redirect to login page
  }
};

// 9. Default Theme Configuration
const defaultThemeConfig = {
  theme: {
    primaryColor: '#8E24AA', // A nice shade of purple
    secondaryColor: '#FFC107', // An amber yellow
    fontSize: '18px',
    fontFamily: 'Arial, sans-serif'
  }
};

// 10. Helper function to generate a styled HTML page
const generateThemedPage = (pageBody, themeConfig, title = 'Theme Configuration App') => {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${escapeHtml(title)}</title>
      <style>
        body {
          font-family: ${escapeHtml(themeConfig.theme.fontFamily)};
          background-color: #121212;
          color: #E0E0E0;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          padding: 20px;
          flex-direction: column;
          gap: 20px;
        }
        .container {
          max-width: 800px;
          padding: 40px;
          border-radius: 10px;
          background-color: #1E1E1E;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
          text-align: center;
          width: 100%;
        }
        .form-container {
            max-width: 800px;
            padding: 20px;
            border-radius: 10px;
            background-color: #1E1E1E;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            width: 100%;
        }
        h1 {
          color: ${escapeHtml(themeConfig.theme.primaryColor)};
          font-size: 2.5rem;
          margin-bottom: 0.5rem;
        }
        p {
          font-size: ${escapeHtml(themeConfig.theme.fontSize)};
          line-height: 1.6;
        }
        a {
          color: ${escapeHtml(themeConfig.theme.primaryColor)};
          text-decoration: none;
          font-weight: bold;
          transition: color 0.3s ease;
        }
        a:hover {
          text-decoration: underline;
          color: ${escapeHtml(themeConfig.theme.secondaryColor)};
        }
        pre {
          background-color: #000000;
          color: #00FF00;
          padding: 20px;
          border-radius: 8px;
          border: 1px solid ${escapeHtml(themeConfig.theme.secondaryColor)};
          overflow-x: auto;
          text-align: left;
        }
        form {
          display: flex;
          flex-direction: column;
          gap: 15px;
          text-align: left;
        }
        label {
          font-weight: bold;
          color: #E0E0E0;
        }
        input[type="text"], input[type="password"], input[type="color"] {
          width: 100%;
          padding: 8px;
          border-radius: 5px;
          border: 1px solid ${escapeHtml(themeConfig.theme.primaryColor)};
          background-color: #2D2D2D;
          color: #E0E0E0;
          box-sizing: border-box;
        }
        input[type="color"] {
            padding: 0;
            height: 40px;
        }
        button {
          background-color: ${escapeHtml(themeConfig.theme.primaryColor)};
          color: #fff;
          border: none;
          padding: 12px 20px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 1rem;
          font-weight: bold;
          transition: background-color 0.3s ease;
        }
        button:hover {
          background-color: ${escapeHtml(themeConfig.theme.secondaryColor)};
        }
        .error-message {
            color: #FF6B6B;
            font-size: 0.9rem;
            text-align: center;
        }
      </style>
    </head>
    <body>
      ${pageBody}
    </body>
    </html>
  `;
};

// 11. Registration Routes
app.get('/register', (req, res) => {
  const errorMessage = req.session.errorMessage;
  req.session.errorMessage = null; // Clear the error message after displaying it
  const errorHtml = errorMessage ? `<p class="error-message">${escapeHtml(errorMessage)}</p>` : '';

  const pageBody = `
    <div class="container">
      <h1>Register</h1>
      ${errorHtml}
      <form action="/register" method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Register</button>
      </form>
      <p>Already have an account? <a href="/login">Login here</a></p>
    </div>
  `;
  res.send(generateThemedPage(pageBody, defaultThemeConfig, 'Register'));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    req.session.errorMessage = 'User already exists!';
    return res.redirect('/register');
  }
  
  // Storing the password in plaintext for the CTF scenario.
  // DO NOT do this in a real application!
  users[username] = {
    password: password,
    isAdmin: false,
    themeConfig: {
      theme: {
        primaryColor: '#6200EE',
        secondaryColor: '#03DAC6',
        fontSize: '16px',
        fontFamily: 'Roboto, sans-serif'
      }
    }
  };
  
  req.session.userId = username;
  res.redirect('/');
});

// 12. Login Routes
app.get('/login', (req, res) => {
  const errorMessage = req.session.errorMessage;
  req.session.errorMessage = null; // Clear the error message after displaying it
  const errorHtml = errorMessage ? `<p class="error-message">${escapeHtml(errorMessage)}</p>` : '';

  const pageBody = `
    <div class="container">
      <h1>Login</h1>
      ${errorHtml}
      <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
      </form>
      <p>Don't have an account? <a href="/register">Register here</a></p>
    </div>
  `;
  res.send(generateThemedPage(pageBody, defaultThemeConfig, 'Login'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  // Comparing the plaintext password for the CTF scenario.
  // DO NOT do this in a real application!
  if (user && user.password === password) {
    req.session.userId = username;
    res.redirect('/');
  } else {
    req.session.errorMessage = 'Invalid username or password';
    res.redirect('/login');
  }
});

// 13. Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out.');
    }
    res.redirect('/login');
  });
});

// 14. Define the root endpoint (protected)
app.get('/', isAuthenticated, (req, res) => {
  const user = users[req.session.userId];
  if (!user) {
    return res.redirect('/login');
  }
  
  const themeConfig = user.themeConfig;
  
  const pageBody = `
    <div class="container">
      <h1>Welcome, ${escapeHtml(req.session.userId)}!</h1>
      <p>Current Theme Configuration:</p>
      <pre>${escapeHtml(JSON.stringify(themeConfig, null, 2))}</pre>
      <p><a href="/logout">Logout</a></p>
    </div>

    <div class="form-container">
      <h2>Customize Theme</h2>
      <form action="/theme" method="GET">
        <label for="primaryColor">Primary Color:</label>
        <input type="color" id="primaryColor" name="theme.primaryColor" value="${escapeHtml(themeConfig.theme.primaryColor)}">

        <label for="secondaryColor">Secondary Color:</label>
        <input type="color" id="secondaryColor" name="theme.secondaryColor" value="${escapeHtml(themeConfig.theme.secondaryColor)}">

        <label for="fontSize">Font Size (e.g., '16px'):</label>
        <input type="text" id="fontSize" name="theme.fontSize" value="${escapeHtml(themeConfig.theme.fontSize)}">

        <label for="fontFamily">Font Family (e.g., 'Roboto, sans-serif'):</label>
        <input type="text" id="fontFamily" name="theme.fontFamily" value="${escapeHtml(themeConfig.theme.fontFamily)}">
        
        <button type="submit">Update Theme</button>
      </form>
    </div>
  `;
  res.send(generateThemedPage(pageBody, themeConfig));
});


// 15. Define the `/theme` endpoint (protected)
app.get('/theme', isAuthenticated, (req, res) => {
  const user = users[req.session.userId];
  if (!user) {
    // This case should be handled by isAuthenticated middleware, but is here as a fallback
    return res.redirect('/login');
  }

  // Parse the query string into a nested object
  const queryString = req.url.split('?')[1] || '';
  const parsedUpdates = parseQueryParams(queryString);

  // If there are updates, merge them into the existing config.
  if (Object.keys(parsedUpdates).length > 0) {
    // Merge the parsed updates into the user's theme config.
    user.themeConfig = deepMerge(user.themeConfig, parsedUpdates);
  }

  // Redirect the user back to the home page to see the updated theme.
  res.redirect('/');
});

// 15. Define the `/flag` endpoint (protected)
app.get('/flag', isAuthenticated, (req, res, next)=>{
  if(users[req.session.userId].isAdmin == true){
    return res.end(FLAG);
  }
  return res.end("Not admin :(");
});

// 16. Start the Express server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
  console.log('Please register or login at http://localhost:3000/register or http://localhost:3000/login');
});

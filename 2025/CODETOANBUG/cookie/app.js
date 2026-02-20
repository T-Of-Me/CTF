const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const app = express();
const PORT = 4300;

const adminCookieValue = "fake_cookie";
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

let logs = [];
let csrfSuccess = false;

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.post('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/attacker', (req, res) => res.sendFile(path.join(__dirname, 'attacker.html')));
app.get('/log', (req, res) => res.sendFile(path.join(__dirname, 'log.html')));
app.get('/bot', (req, res) => res.sendFile(path.join(__dirname, 'bot.html')));
app.get('/test', (req, res) => res.sendFile(path.join(__dirname, 'test.html')));

app.post('/save-script', (req, res) => {
    const { script } = req.body;
    fs.writeFileSync(path.join(__dirname, 'test.html'), script);
    logs.push(`Saved script: ${script}`);
    res.json({ message: 'Script saved successfully!' });
});

app.post('/send-script', (req, res) => {
    logs.push('Script sent to bot for execution.');
    csrfSuccess = true;
    res.json({ message: 'Script sent to bot!' });
});

app.get('/get-log', (req, res) => {
    res.json({ logs });
});

app.get('/get-flag', (req, res) => {
    const cookie = req.cookies.admin_session;
    if (cookie === adminCookieValue) {
        const flag = "CODE_TOAN_BUG{fake_flag}";
        logs.push('Flag accessed from bot.');
        res.send(flag);
    } else {
        res.status(403).send('Access denied: invalid cookie.');
    }
});

app.get('/bot', (req, res) => {
    if (csrfSuccess) {
        logs.push('Bot accessed, admin cookie returned.');
        res.json({ cookie: `admin_session=${adminCookieValue}` });
    } else {
        res.json({ message: 'CSRF attack not detected, no cookie returned.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://10.0.1.1:${PORT}`);
});

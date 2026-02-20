const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 4200;
const flag = "CODE_TOAN_BUG{fake_flag}";
const accessKey = "delete_key";

app.use(express.urlencoded({ extended: true }));

function loadHTML(filename) {
    return fs.readFileSync(path.join(__dirname, filename), 'utf8');
}

app.get('/', (req, res) => {
    const htmlContent = loadHTML('index.html');
    res.send(htmlContent);
});

app.get('/dashboard/endpoint', (req, res) => {
    const key = req.query.access_key;

    if (key && key.trim() === accessKey) {
        res.send(`<p>Flag: ${flag}</p>`);
    } else {
        res.send(`
            <p>Access key is incorrect or missing. Please try again.</p>
            <p>Remember, this is a test of your skills!</p>
            <a href="/">Go Back</a>
        `);
    }
});

app.get('/read', (req, res) => {
    const fileParam = req.query.file || '';
    const allowedFile = 'accesskey.txt';

    if (fileParam === allowedFile) {
        const filePath = path.join(__dirname, allowedFile);
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return res.status(404).send("File not found.");
            }
            res.send(`<pre>${data}</pre>`);
        });
    } else {
        res.send('Invalid file requested. Only accesskey.txt can be read.');
    }
});

app.get('/script.js', (req, res) => {
    res.send(`
        document.addEventListener('DOMContentLoaded', () => {
            const button = document.getElementById('jokeButton');
            button.addEventListener('click', () => {
                fetch('/joke')
                    .then(response => response.text())
                    .then(data => {
                        document.getElementById('jokeContainer').innerHTML = data;
                    });
            });
        });
    `);
});

app.get('/index.html', (req, res) => {
    const content = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CTF Challenge</title>
            <link rel="stylesheet" href="style.css">
            <script src="/script.js"></script>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to the CTF Challenge!</h1>
                <p>Try to access the flag by entering the correct access key.</p>
                <form action="/hidden/flag" method="get">
                    <input type="text" name="access_key" placeholder="Enter access key" required />
                    <button type="submit">Submit</button>
                </form>
                <div id="jokeContainer"></div>
                <button id="jokeButton">Get a Random Joke</button>
                <h2>Read the Access Key (Path Traversal)</h2>
                <form action="/read" method="get">
                    <input type="text" name="file" placeholder="Enter file name (accesskey.txt)" required />
                    <button type="submit">Read File</button>
                </form>
            </div>
        </body>
        </html>
    `;
    res.send(content);
});

app.get('/joke', (req, res) => {
    const jokes = [
        "Why did the scarecrow win an award? Because he was outstanding in his field!",
        "Why don't skeletons fight each other? They don't have the guts!",
        "What do you call fake spaghetti? An impasta!",
        "What did one wall say to the other wall? I'll meet you at the corner!",
        "Why don't scientists trust atoms? Because they make up everything!"
    ];
    const randomJoke = jokes[Math.floor(Math.random() * jokes.length)];
    res.send(`<p>${randomJoke}</p><a href="/">Back to Home</a>`);
});

app.listen(port, () => {
    console.log(`Server is running on http://10.0.1.1:${port}`);
});

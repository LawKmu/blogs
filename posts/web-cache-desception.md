---
title: "Web Cache Deception: Bending the Rules of Web Cache Exploitation"
date: "2026-02-11"
excerpt: "Web Cache Deception (WCD) isn't a code flaw—it's an architectural trap. Learn how parsing mismatches turn private data into public static files."
coverImage: "https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/web_cache1.png"
tags: ["web", "vulnerability", "cybersecurity", "web-cache-deception"]
---

# Web Cache Deception: Exploiting Architectural Mismatches

> This content is for educational purposes only.\
> This article is based on [PortSwigger research](https://portswigger.net/web-security/web-cache-deception).

---

# What is Web Cache Deception?

Web Cache Deception (WCD) is a vulnerability that occurs when an attacker tricks a caching system into storing **sensitive, dynamic content** as if it were a **public, static resource**.

It is not a traditional code flaw like SQLi or XSS. Instead, it results from a **parsing mismatch** between the caching layer and the origin server. The vulnerability lives in the "gray area" of how two different systems interpret the same URL.


### The Architecture of a Cache

![The Architecture of a Cache](https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/web_cache2.png)

**The Request Flow:**

A cache (CDN or reverse proxy) sits between the client and the origin server to reduce load.

1.  **Request:** The user requests a resource.
2.  **Rule Check:** The cache checks its configuration to see if the URL looks "cacheable" (e.g., ends in `.css`).
3.  **Storage:** If it’s a "miss," the cache fetches it from the origin and saves a copy.
4.  **Delivery:** Future users requesting that exact URL receive the cached version instantly.

**The Gap:**
WCD exploits the discrepancy between:
* **What the cache believes** it is storing (static content).
* **What the origin actually generates** (dynamic, sensitive content).

---

## Attack Methodology

The attack is conceptually simple. Imagine you are logged into your bank. Your profile contains your balance and transaction history. 

To boost speed, the bank caches files ending in: `.css`, `.js`, `.png`, `.jpg`.

An attacker crafts a URL like this: `https://bank.com/account/profile/nonexistent.css`

1.  **The Cache** sees `.css` at the end. It thinks: *"This is a stylesheet. If the server returns a 200 OK, I'll cache it for everyone."*
2.  **The Origin Server** receives the request. Due to flexible routing, it ignores the `/nonexistent.css` suffix and serves your **private profile page**.
3.  **The Result:** The cache stores your private HTML under the name `nonexistent.css`. The attacker now simply visits that URL and views your data.

---

## Exploitation Techniques

![Web Cache Deception Flow](https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/web_cache3.png)

### 1. Path Mapping Discrepancies

The risk appears when the cache uses file-extension rules while the application uses flexible routing.

* **Traditional Mapping:** `https://example.com/assets/logo.png` maps directly to a physical file.
* **REST-Style Mapping:** `https://example.com/users/123/profile` maps to an API logic.

If an attacker appends a fake extension (`/profile/test.js`), and the server still serves the profile because it "ignores" the trailing path, the cache is successfully deceived.

![Path Mapping Discrepancies](https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/web_cache4.png)
---

### 2. Delimiter Discrepancies

A delimiter (like `?`, `#`, or `;`) tells a server where the URL path ends. WCD occurs when the **cache** and the **origin server** disagree on which character is a delimiter.



* **The Cache's Perspective:** It may only recognize `?`. It sees `/profile;index.css` as a single file path ending in `.css`. **Result: Cacheable.**
* **The Origin's Perspective:** It might use a framework (like Spring) that treats `;` as a delimiter. It sees `/profile` and ignores the rest. **Result: Sensitive Data.**

**Common Delimiters to Test:**
* Semicolons (`;`)
* Dots (`.`)
* Null Bytes (`%00`)
* Newlines (`%0a`)


![Delimiter Discrepancies](https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/web_cache5.png)
---

### 3. Normalization

Normalization is how a server "cleans up" a URL (e.g., resolving `/../`). If the cache and origin normalize the URL in a different order, the attacker wins.



**Path Traversal Example:** `/profile/..%2fassets/style.css`

1.  **The Cache:** Does not decode the `%2f` (`/`). It sees a URL ending in `style.css` and caches it.
2.  **The Origin:** Decodes the `%2f` and normalizes the path. It resolves `/profile/../assets/style.css` back to `/profile`.
3.  **The Deception:** The cache saves the private HTML of `/profile` under the key of the "static" CSS path.


![Normalization](https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/web_cache6.png)
---

## Testing & Detection

### Testing Tools
* **Burp Suite:** Use the "Web Cache Deception Scanner" extension.
* **Manual Testing:** Manually append suffixes like `.css` or `.js` to sensitive endpoints.
* **Header Analysis:** Look for these indicators:
    * `X-Cache: HIT`
    * `Cache-Control: public`
    * `Age: [seconds]`

---

## Prevention Strategies

| Strategy | Implementation |
| :--- | :--- |
| **Strict Cache Rules** | Only cache files from specific folders like `/static/`. |
| **Header Control** | Force `Cache-Control: no-store, private` on sensitive pages. |
| **Disable Path Info** | Configure origin servers to reject requests with extra path info. |
| **Consistency** | Ensure both layers use identical URL normalization logic. |

---

## Summary

Web Cache Deception is powerful because it exploits **trust**. The cache trusts the extension, and the origin trusts the cache. By breaking that trust, attackers turn a performance tool into a data leak.


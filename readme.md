# 🔐 Signature-Based Authentication

**Cryptographic signature-based authentication using secp256k1 elliptic curve digital signatures**

[
[
[

> **Simple, secure, and cross-platform cryptographic authentication without passwords**

## ✨ Features

- 🚀 **Zero dependencies** on external auth services
- 🔒 **Cryptographically secure** using secp256k1 (same as Bitcoin)
- 🌐 **Cross-platform** - Works in Node.js and browsers
- ⚡ **Lightweight** - Minimal footprint
- 🛡️ **Replay attack protection** with timestamps and nonces
- 🔑 **No password storage** - Only public keys needed
- 📦 **TypeScript ready** - Full type definitions included

## 🚀 Quick Start

```bash
npm install signature-login
```

```javascript
import { generateKeyPair, createAuth, verifyAuth } from "signature-login";

// 1. Generate cryptographic key pair
const { privateKey, publicKey } = generateKeyPair();

// 2. Create authentication signature (client-side)
const authHeaders = await createAuth(privateKey);

// 3. Verify signature (server-side)
const verifiedPublicKey = await verifyAuth(authHeaders);

if (verifiedPublicKey) {
  console.log("✅ Authentication successful!");
  console.log("User public key:", verifiedPublicKey);
} else {
  console.log("❌ Authentication failed");
}
```

## 📖 API Reference

### `generateKeyPair()`

Generates a new secp256k1 key pair.

```javascript
const { privateKey, publicKey } = generateKeyPair();
// privateKey: "a1b2c3d4..." (64 chars)
// publicKey: "02a1b2c3d4..." (66 chars, compressed)
```

### `createAuth(privateKeyHex)`

Creates authentication headers with timestamp and nonce for replay protection.

```javascript
const auth = await createAuth(privateKey);
console.log(auth);
// {
//   publickey: "02a1b2c3d4...",
//   signature: "3045022100...",
//   message: "1642680123456:a1b2c3d4e5f6...",
//   timestamp: 1642680123456,
//   nonce: "a1b2c3d4e5f6..."
// }
```

### `verifyAuth(authHeaders, maxAgeMs?)`

Verifies authentication headers. Returns public key if valid, `null` if invalid.

```javascript
const result = await verifyAuth(authHeaders);
// Returns: publicKey string or null

// Custom timeout (default: 5 minutes)
const result = await verifyAuth(authHeaders, 10 * 60 * 1000); // 10 minutes
```

### Low-level Functions

```javascript
// Sign any message
const signature = await sign("Hello World", privateKey);

// Verify any signature
const isValid = await verify("Hello World", signature, publicKey);

// Hash function
const hash = await sha256("Hello World");
```

## 🌐 Express.js Integration

```javascript
import express from "express";
import { verifyAuth } from "signature-login";

const app = express();

// Authentication middleware
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers["x-signature-auth"];

  if (!authHeader) {
    return res.status(401).json({ error: "Missing authentication" });
  }

  try {
    const authData = JSON.parse(authHeader);
    const publicKey = await verifyAuth(authData);

    if (!publicKey) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    req.userPublicKey = publicKey;
    next();
  } catch (error) {
    res.status(400).json({ error: "Malformed auth header" });
  }
};

// Protected route
app.get("/protected", authMiddleware, (req, res) => {
  res.json({
    message: "Success!",
    user: req.userPublicKey,
  });
});
```

## 🌍 Browser Usage

```html
<!DOCTYPE html>
<html>
  <head>
    <script type="module">
      import {
        generateKeyPair,
        createAuth,
      } from "https://unpkg.com/signature-login@latest/index.js";

      async function login() {
        // Generate or load existing keys
        const { privateKey } = generateKeyPair();

        // Create auth signature
        const auth = await createAuth(privateKey);

        // Send to server
        fetch("/api/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Signature-Auth": JSON.stringify(auth),
          },
        });
      }
    </script>
  </head>
</html>
```

## 🔒 Security Features

### Replay Attack Protection

- **Timestamps**: Each signature includes current timestamp
- **Nonces**: Random 16-byte nonce prevents duplicate signatures
- **Expiration**: Signatures expire after 5 minutes (configurable)

### Cryptographic Security

- **secp256k1**: Same elliptic curve used by Bitcoin
- **SHA-256**: Industry standard hashing
- **Deterministic signatures**: Uses RFC 6979 for signature generation

## 🏗️ Architecture

```
Client                           Server
------                           ------
generateKeyPair() ──────────────▶ Store publicKey in database
       │
       ▼
createAuth(privateKey) ──────────▶ verifyAuth(authHeaders)
       │                                   │
       ▼                                   ▼
Send signature ─────────────────▶ Returns publicKey or null
```

## 🛠️ Advanced Usage

### Custom Message Signing

```javascript
import { sign, verify } from "signature-login";

// Sign custom data
const data = JSON.stringify({ action: "transfer", amount: 100 });
const signature = await sign(data, privateKey);

// Verify later
const isValid = await verify(data, signature, publicKey);
```

### Key Storage Best Practices

```javascript
// ❌ Don't store private keys in plain text
localStorage.setItem("privateKey", privateKey);

// ✅ Use secure storage
const encryptedKey = await encrypt(privateKey, userPassword);
localStorage.setItem("encryptedKey", encryptedKey);

// ✅ Or use hardware wallets, secure enclaves, etc.
```

## 📊 Performance

- **Key generation**: ~2ms
- **Signature creation**: ~1ms
- **Signature verification**: ~2ms
- **Bundle size**: ~45KB minified

**Made with ❤️ for the crypto community**

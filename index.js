// Signature-Login: Cross-platform cryptographic login/verify module
import * as secp from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { createHash, randomBytes as nodeRandomBytes } from "crypto";
import { TextEncoder } from "util";

// Set up HMAC for secp256k1
secp.etc.hmacSha256Sync = (key, ...msgs) => hmac(nobleSha256, key, secp.etc.concatBytes(...msgs));

// Browser compatibility
const encoder = typeof window !== "undefined" ? new window.TextEncoder() : new TextEncoder();

// Helper function to convert bytes to hex
function bytesToHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Helper function to convert hex to bytes
function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Helper function to generate random bytes
function randomBytes(length) {
  if (typeof window !== "undefined" && window.crypto) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return bytes;
  } else {
    return new Uint8Array(nodeRandomBytes(length));
  }
}

// --- Key Generation ---
export function generateKeyPair() {
  const privateKey = secp.utils.randomPrivateKey();
  const publicKey = secp.getPublicKey(privateKey, true); // compressed
  return {
    privateKey: bytesToHex(privateKey),
    publicKey: bytesToHex(publicKey),
  };
}

// --- Hashing (SHA-256) ---
export async function sha256(msg) {
  const encoded = encoder.encode(msg);
  
  if (typeof window === "undefined") {
    // Node.js
    return new Uint8Array(createHash("sha256").update(encoded).digest());
  } else {
    // Browser
    const hash = await window.crypto.subtle.digest("SHA-256", encoded);
    return new Uint8Array(hash);
  }
}

// --- Sign Message ---
export async function sign(message, privateKeyHex) {
  const hash = await sha256(message);
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const sig = secp.sign(hash, privateKeyBytes);
  return bytesToHex(sig.toCompactRawBytes());
}

// --- Verify Signature ---
export async function verify(message, signatureHex, publicKeyHex) {
  try {
    const hash = await sha256(message);
    const signatureBytes = hexToBytes(signatureHex);
    const publicKeyBytes = hexToBytes(publicKeyHex);
    return secp.verify(signatureBytes, hash, publicKeyBytes);
  } catch {
    return false;
  }
}

// --- Auth Header Helper ---
export async function createAuth(privateKeyHex) {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKeyBytes = secp.getPublicKey(privateKeyBytes, true);
  const publicKeyHex = bytesToHex(publicKeyBytes);

  const timestamp = Date.now();
  const nonceBytes = randomBytes(16);
  const nonce = bytesToHex(nonceBytes);
  const message = `${timestamp}:${nonce}`;
  
  const signature = await sign(message, privateKeyHex);
  return { 
    publickey: publicKeyHex, 
    signature, 
    message,
    timestamp,
    nonce
  };
}

// --- Verify Auth Headers ---
export async function verifyAuth(authHeaders, maxAgeMs = 5 * 60 * 1000) {
  try {
    const publicKeyHex = authHeaders.publickey || authHeaders.publicKeyHex;
    const { signature, message } = authHeaders;
    
    if (!publicKeyHex || !signature || !message) {
      return null;
    }
    
    // Extract timestamp from message
    const timestamp = Number(message.split(':')[0]);
    
    // Check timestamp is within maxAge
    const now = Date.now();
    if (isNaN(timestamp) || Math.abs(now - timestamp) > maxAgeMs) {
      return null;
    }
    
    // Verify signature
    const isValid = await verify(message, signature, publicKeyHex);
    if (!isValid) {
      return null;
    }
    
    return publicKeyHex;
    
  } catch {
    return null;
  }
}

// --- Export noble secp for advanced users ---
export { secp };

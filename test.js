import { 
  generateKeyPair, 
  sign, 
  verify, 
  createAuth, 
  verifyAuth,
  sha256
} from './index.js';

async function runTests() {
  console.log('🧪 Running Signature Login Tests...\n');
  
  let passed = 0;
  let failed = 0;
  
  function test(name, testFn) {
    try {
      const result = testFn();
      if (result instanceof Promise) {
        return result.then(() => {
          console.log(`✅ ${name}`);
          passed++;
        }).catch(err => {
          console.log(`❌ ${name}: ${err.message}`);
          failed++;
        });
      } else {
        console.log(`✅ ${name}`);
        passed++;
      }
    } catch (err) {
      console.log(`❌ ${name}: ${err.message}`);
      failed++;
    }
  }
  
  function expect(value) {
    return {
      toBe: (expected) => {
        if (value !== expected) throw new Error(`Expected ${expected}, got ${value}`);
      },
      toEqual: (expected) => {
        if (JSON.stringify(value) !== JSON.stringify(expected)) {
          throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
        }
      },
      toHaveLength: (expected) => {
        if (value.length !== expected) throw new Error(`Expected length ${expected}, got ${value.length}`);
      }
    };
  }

  const keyPair = generateKeyPair();

  // Run tests
  await test('should generate valid key pairs', () => {
    const { privateKey, publicKey } = generateKeyPair();
    expect(privateKey).toHaveLength(64);
    expect(publicKey).toHaveLength(66);
  });

  await test('should hash messages consistently', async () => {
    const message = "test message";
    const hash1 = await sha256(message);
    const hash2 = await sha256(message);
    
    expect(hash1).toEqual(hash2);
    expect(hash1).toHaveLength(32);
  });

  await test('should sign and verify messages', async () => {
    const message = "test message";
    const signature = await sign(message, keyPair.privateKey);
    const isValid = await verify(message, signature, keyPair.publicKey);
    
    expect(signature).toHaveLength(128);
    expect(isValid).toBe(true);
  });

  await test('should fail verification with wrong key', async () => {
    const message = "test message";
    const signature = await sign(message, keyPair.privateKey);
    
    const wrongKeyPair = generateKeyPair();
    const isValid = await verify(message, signature, wrongKeyPair.publicKey);
    
    expect(isValid).toBe(false);
  });

  await test('should create and verify auth headers', async () => {
    const auth = await createAuth(keyPair.privateKey);
    const result = await verifyAuth(auth);
    
    expect(auth.publickey).toBe(keyPair.publicKey);
    expect(auth.signature).toHaveLength(128);
    expect(auth.nonce).toHaveLength(32);
    expect(result).toBe(keyPair.publicKey);
  });

  await test('should reject expired auth headers', async () => {
    const auth = await createAuth(keyPair.privateKey);
    
    // Override timestamp to be old
    auth.timestamp = Date.now() - 10 * 60 * 1000;
    auth.message = `${auth.timestamp}:${auth.nonce}`;
    
    const result = await verifyAuth(auth);
    expect(result).toBe(null);
  });

  await test('should handle missing fields', async () => {
    const incompleteAuth = { publickey: keyPair.publicKey };
    const result = await verifyAuth(incompleteAuth);
    
    expect(result).toBe(null);
  });

  await test('should work with both publickey and publicKeyHex', async () => {
    const auth = await createAuth(keyPair.privateKey);
    
    // Test with publickey
    const result1 = await verifyAuth(auth);
    expect(result1).toBe(keyPair.publicKey);
    
    // Test with publicKeyHex
    auth.publicKeyHex = auth.publickey;
    delete auth.publickey;
    const result2 = await verifyAuth(auth);
    expect(result2).toBe(keyPair.publicKey);
  });

  console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
  
  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('🎉 All tests passed!');
  }
}

runTests().catch(console.error);

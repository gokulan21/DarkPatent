class CryptoUtils {
  constructor() {
    this.algorithm = 'AES-GCM';
    this.keyLength = 256;
    this.ivLength = 12; // 96 bits for GCM
  }

  async generateKey() {
    return await crypto.subtle.generateKey(
      {
        name: this.algorithm,
        length: this.keyLength,
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      passwordKey,
      {
        name: this.algorithm,
        length: this.keyLength,
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async encrypt(data, key) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
    const encrypted = await crypto.subtle.encrypt(
      {
        name: this.algorithm,
        iv: iv,
      },
      key,
      encoder.encode(data)
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return this.arrayBufferToBase64(combined);
  }

  async decrypt(encryptedData, key) {
    const combined = this.base64ToArrayBuffer(encryptedData);
    const iv = combined.slice(0, this.ivLength);
    const encrypted = combined.slice(this.ivLength);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: this.algorithm,
        iv: iv,
      },
      key,
      encrypted
    );
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  async hash(data) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return this.arrayBufferToHex(hashBuffer);
  }

  async generateHMAC(data, key) {
    const encoder = new TextEncoder();
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(key),
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(data));
    return this.arrayBufferToHex(signature);
  }

  async verifyHMAC(data, signature, key) {
    const encoder = new TextEncoder();
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(key),
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      false,
      ['verify']
    );
    return await crypto.subtle.verify('HMAC', hmacKey, this.hexToArrayBuffer(signature), encoder.encode(data));
  }

  generateSecureToken(length = 32) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => chars[byte % chars.length]).join('');
  }

  async deriveKey(masterKey, purpose, salt) {
    const encoder = new TextEncoder();
    const purposeBuffer = encoder.encode(purpose);
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: purposeBuffer,
      },
      masterKey,
      {
        name: this.algorithm,
        length: this.keyLength,
      },
      false,
      ['encrypt', 'decrypt']
    );
    return derivedKey;
  }

  secureWipe(data) {
    if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
      const view = new Uint8Array(data);
      crypto.getRandomValues(view);
    } else if (typeof data === 'string') {
      data = null;
    }
  }

  arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary);
  }

  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      view[i] = binary.charCodeAt(i);
    }
    return buffer;
  }

  arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  hexToArrayBuffer(hex) {
    const buffer = new ArrayBuffer(hex.length / 2);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < hex.length; i += 2) {
      view[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return buffer;
  }

  constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  sanitizeForStorage(data) {
    if (typeof data === 'string') {
      return data.replace(/[<>]/g, '');
    }
    return data;
  }
}
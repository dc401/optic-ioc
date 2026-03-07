//Optic IOC - Cryptography Utilities
//Production-ready AES-256-GCM encryption using Web Crypto API
//Keys derived from OAuth token using PBKDF2

class CryptoManager {
  constructor() {
    this.subtle = crypto.subtle;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
  }

  //Generate cryptographically secure random bytes
  getRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  //Convert ArrayBuffer to base64 string
  bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  //Convert base64 string to ArrayBuffer
  base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  //Derive encryption key from OAuth token using PBKDF2
  //token: OAuth token string
  //salt: Uint8Array of random salt
  //returns: CryptoKey for AES-GCM
  async deriveKey(token, salt) {
    if (!token || token.length < 16) {
      throw new Error('Invalid token for key derivation');
    }

    //Import token as key material
    const keyMaterial = await this.subtle.importKey(
      'raw',
      this.encoder.encode(token),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    //Derive AES-GCM key
    const key = await this.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: OPTIC_CONSTANTS.CRYPTO.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      {
        name: OPTIC_CONSTANTS.CRYPTO.ALGORITHM,
        length: OPTIC_CONSTANTS.CRYPTO.KEY_LENGTH
      },
      false, //not extractable
      ['encrypt', 'decrypt']
    );

    return key;
  }

  //Encrypt plaintext using AES-256-GCM
  //plaintext: string to encrypt
  //token: OAuth token for key derivation
  //returns: { ciphertext, nonce, salt } as base64 strings
  async encrypt(plaintext, token) {
    try {
      //Validate inputs
      if (!plaintext) {
        throw new Error('Plaintext is required');
      }
      if (!token || token.length < 16) {
        throw new Error('Valid OAuth token required');
      }

      //Generate random salt and nonce
      const salt = this.getRandomBytes(OPTIC_CONSTANTS.CRYPTO.SALT_LENGTH);
      const nonce = this.getRandomBytes(OPTIC_CONSTANTS.CRYPTO.IV_LENGTH);

      //Derive key
      const key = await this.deriveKey(token, salt);

      //Encrypt
      const plaintextBytes = this.encoder.encode(plaintext);
      const ciphertext = await this.subtle.encrypt(
        {
          name: OPTIC_CONSTANTS.CRYPTO.ALGORITHM,
          iv: nonce,
          tagLength: OPTIC_CONSTANTS.CRYPTO.TAG_LENGTH
        },
        key,
        plaintextBytes
      );

      //Return as base64 strings
      return {
        ciphertext: this.bufferToBase64(ciphertext),
        nonce: this.bufferToBase64(nonce),
        salt: this.bufferToBase64(salt),
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error('Encryption failed: ' + error.message);
    }
  }

  //Decrypt ciphertext using AES-256-GCM
  //encrypted: { ciphertext, nonce, salt } as base64 strings
  //token: OAuth token for key derivation
  //returns: decrypted plaintext string
  async decrypt(encrypted, token) {
    try {
      //Validate inputs
      if (!encrypted || !encrypted.ciphertext || !encrypted.nonce || !encrypted.salt) {
        throw new Error('Invalid encrypted data structure');
      }
      if (!token || token.length < 16) {
        throw new Error('Valid OAuth token required');
      }

      //Convert from base64
      const ciphertext = this.base64ToBuffer(encrypted.ciphertext);
      const nonce = this.base64ToBuffer(encrypted.nonce);
      const salt = this.base64ToBuffer(encrypted.salt);

      //Derive key (same salt as encryption)
      const key = await this.deriveKey(token, new Uint8Array(salt));

      //Decrypt
      const plaintextBytes = await this.subtle.decrypt(
        {
          name: OPTIC_CONSTANTS.CRYPTO.ALGORITHM,
          iv: new Uint8Array(nonce),
          tagLength: OPTIC_CONSTANTS.CRYPTO.TAG_LENGTH
        },
        key,
        ciphertext
      );

      //Return as string
      return this.decoder.decode(plaintextBytes);
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Decryption failed - wrong token or corrupted data');
    }
  }

  //Encrypt multiple secrets as a batch
  //secrets: object like { gti: 'key1', internal_ti: 'key2' }
  //token: OAuth token
  //returns: object with encrypted values
  async encryptSecrets(secrets, token) {
    const encrypted = {};
    for (const [id, value] of Object.entries(secrets)) {
      if (value && value.trim()) {
        encrypted[id] = await this.encrypt(value, token);
      }
    }
    return encrypted;
  }

  //Decrypt multiple secrets as a batch
  //encryptedSecrets: object with encrypted values
  //token: OAuth token
  //returns: object with plaintext values
  async decryptSecrets(encryptedSecrets, token) {
    const decrypted = {};
    for (const [id, encrypted] of Object.entries(encryptedSecrets)) {
      try {
        decrypted[id] = await this.decrypt(encrypted, token);
      } catch (error) {
        console.error(`Failed to decrypt secret '${id}':`, error);
        decrypted[id] = null; //mark as failed
      }
    }
    return decrypted;
  }

  //Verify if encrypted data is valid (can be decrypted)
  //encrypted: encrypted data object
  //token: OAuth token
  //returns: boolean
  async verifyEncrypted(encrypted, token) {
    try {
      await this.decrypt(encrypted, token);
      return true;
    } catch {
      return false;
    }
  }
}

//Export singleton instance
const cryptoManager = new CryptoManager();

//For use in service worker modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = cryptoManager;
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.cryptoManager = cryptoManager;
  self.CryptoManager = CryptoManager;
}

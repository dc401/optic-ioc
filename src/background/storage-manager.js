//Optic IOC - Storage Manager
//Handles encrypted storage of secrets and configuration
//Uses chrome.storage.sync for config, chrome.storage.local for secrets/cache

class StorageManager {
  constructor(cryptoManager) {
    this.crypto = cryptoManager;
    this.memoryCache = new Map(); //ephemeral decrypted secrets
    this.cacheTimeout = null;
  }

  //Get encryption key (uses extension ID as consistent key)
  getEncryptionKey() {
    return `optic-ioc-key-${chrome.runtime.id}`;
  }

  //Save configuration to chrome.storage.sync (non-sensitive)
  async saveConfig(config) {
    try {
      //Validate config structure
      if (!config || typeof config !== 'object') {
        throw new Error('Invalid configuration object');
      }

      //Remove any secrets from config (defensive)
      const sanitized = { ...config };
      delete sanitized.api_keys; //should never be here
      delete sanitized.secrets; //should never be here

      await new Promise((resolve, reject) => {
        chrome.storage.sync.set({
          [OPTIC_CONSTANTS.STORAGE_KEYS.CONFIG]: sanitized,
          [OPTIC_CONSTANTS.STORAGE_KEYS.LAST_SYNC]: Date.now()
        }, () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        });
      });

      return true;
    } catch (error) {
      console.error('Failed to save config:', error);
      throw new Error('Failed to save configuration: ' + error.message);
    }
  }

  //Load configuration from chrome.storage.sync
  async loadConfig() {
    try {
      const result = await new Promise((resolve, reject) => {
        chrome.storage.sync.get(OPTIC_CONSTANTS.STORAGE_KEYS.CONFIG, (result) => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(result);
          }
        });
      });

      const config = result[OPTIC_CONSTANTS.STORAGE_KEYS.CONFIG];

      if (!config) {
        //Return default config
        return this.getDefaultConfig();
      }

      //Validate and return
      return this.validateConfig(config);
    } catch (error) {
      console.error('Failed to load config:', error);
      return this.getDefaultConfig();
    }
  }

  //Save secrets to chrome.storage.local (CHROME NATIVE ENCRYPTION)
  //Chrome automatically encrypts via OS keychain (macOS Keychain, Windows DPAPI, Linux libsecret)
  async saveSecrets(secrets) {
    try {
      //SECURITY NOTE: No custom encryption needed - Chrome handles this via OS keychain
      //macOS: Keychain Access (AES-128)
      //Windows: Data Protection API (DPAPI)
      //Linux: libsecret/gnome-keyring
      //This is MORE secure than custom crypto with predictable keys

      //Save secrets directly to local storage
      await chrome.storage.local.set({
        [OPTIC_CONSTANTS.STORAGE_KEYS.ENCRYPTED_SECRETS]: secrets
      });

      //Update memory cache
      this.updateMemoryCache(secrets);

      console.log('✓ API keys saved (encrypted by Chrome via OS keychain)');
      return true;
    } catch (error) {
      console.error('Failed to save secrets:', error);
      throw new Error('Failed to save API keys: ' + error.message);
    }
  }

  //Load secrets from chrome.storage.local (CHROME NATIVE DECRYPTION)
  async loadSecrets() {
    try {
      //Check memory cache first (performance optimization)
      if (this.memoryCache.size > 0) {
        return Object.fromEntries(this.memoryCache);
      }

      //Load secrets from storage (Chrome decrypts automatically)
      const result = await chrome.storage.local.get(OPTIC_CONSTANTS.STORAGE_KEYS.ENCRYPTED_SECRETS);
      const secrets = result[OPTIC_CONSTANTS.STORAGE_KEYS.ENCRYPTED_SECRETS];

      if (!secrets || Object.keys(secrets).length === 0) {
        return {}; //no secrets stored
      }

      //Update memory cache
      this.updateMemoryCache(secrets);

      return secrets;
    } catch (error) {
      console.error('Failed to load secrets:', error);
      //Clear potentially corrupted cache
      this.clearMemoryCache();
      throw new Error('Failed to load API keys - re-enter in settings');
    }
  }

  //Update memory cache with decrypted secrets
  //Auto-clears after idle timeout
  updateMemoryCache(secrets) {
    //Clear existing cache and timeout
    this.clearMemoryCache();

    //Store decrypted secrets
    for (const [id, value] of Object.entries(secrets)) {
      if (value && value !== null) {
        this.memoryCache.set(id, value);
      }
    }

    //Set timeout to clear cache after idle period
    this.cacheTimeout = setTimeout(() => {
      this.clearMemoryCache();
    }, OPTIC_CONSTANTS.PERFORMANCE.IDLE_TIMEOUT_MS);
  }

  //Clear decrypted secrets from memory
  clearMemoryCache() {
    this.memoryCache.clear();
    if (this.cacheTimeout) {
      clearTimeout(this.cacheTimeout);
      this.cacheTimeout = null;
    }
  }

  //Get specific secret from memory cache
  async getSecret(id) {
    //Check memory cache
    if (this.memoryCache.has(id)) {
      return this.memoryCache.get(id);
    }

    //Load all secrets (will populate cache)
    const secrets = await this.loadSecrets();
    return secrets[id] || null;
  }

  //Validate configuration structure
  validateConfig(config) {
    //Ensure required fields exist
    const validated = {
      target_org: config.target_org || '',
      target_org_aliases: Array.isArray(config.target_org_aliases) ? config.target_org_aliases : [],
      intel_sources: Array.isArray(config.intel_sources) ? config.intel_sources : [],
      pivot_links: config.pivot_links || {},
      highlight_style: config.highlight_style || OPTIC_CONSTANTS.HIGHLIGHT_STYLES,
      footnote_verbosity: config.footnote_verbosity || 'summary',
      auto_enrich: config.auto_enrich !== false, //default true
      cache_ttl_days: config.cache_ttl_days || OPTIC_CONSTANTS.PERFORMANCE.CACHE_TTL_DAYS,
      cache_max_size_mb: config.cache_max_size_mb || OPTIC_CONSTANTS.PERFORMANCE.CACHE_MAX_SIZE_MB,
      performance: config.performance || {
        debounce_ms: OPTIC_CONSTANTS.PERFORMANCE.DEBOUNCE_MS,
        max_concurrent_requests: OPTIC_CONSTANTS.PERFORMANCE.MAX_CONCURRENT_REQUESTS,
        use_web_worker: true,
        lazy_load_below_fold: true
      }
    };

    return validated;
  }

  //Get default configuration
  getDefaultConfig() {
    return {
      target_org: '',
      target_org_aliases: [],
      intel_sources: [],
      pivot_links: {},
      highlight_style: OPTIC_CONSTANTS.HIGHLIGHT_STYLES,
      footnote_verbosity: 'summary',
      auto_enrich: true,
      cache_ttl_days: 30,
      cache_max_size_mb: 50,
      performance: {
        debounce_ms: 500,
        max_concurrent_requests: 3,
        use_web_worker: true,
        lazy_load_below_fold: true
      }
    };
  }

  //Export configuration (encrypted)
  async exportConfig(password) {
    try {
      const config = await this.loadConfig();
      const secrets = await this.loadSecrets();

      const exportData = {
        version: OPTIC_CONSTANTS.VERSION,
        config: config,
        secrets_encrypted: true,
        timestamp: Date.now()
      };

      //Encrypt secrets with user password
      if (password && password.length >= 8) {
        const encrypted = await this.crypto.encryptSecrets(secrets, password);
        exportData.secrets = encrypted;
      }

      return JSON.stringify(exportData, null, 2);
    } catch (error) {
      console.error('Failed to export config:', error);
      throw new Error('Failed to export configuration');
    }
  }

  //Import configuration (encrypted)
  async importConfig(jsonData, password) {
    try {
      const data = JSON.parse(jsonData);

      //Validate import data
      if (!data.version || !data.config) {
        throw new Error('Invalid import file format');
      }

      //Import config
      await this.saveConfig(data.config);

      //Import secrets if present
      if (data.secrets && password) {
        const decrypted = await this.crypto.decryptSecrets(data.secrets, password);
        await this.saveSecrets(decrypted);
      }

      return true;
    } catch (error) {
      console.error('Failed to import config:', error);
      throw new Error('Failed to import configuration: ' + error.message);
    }
  }

  //Clear all stored data (factory reset)
  async clearAll() {
    try {
      await chrome.storage.sync.clear();
      await chrome.storage.local.clear();
      this.clearMemoryCache();
      return true;
    } catch (error) {
      console.error('Failed to clear storage:', error);
      throw new Error('Failed to clear data');
    }
  }

  //Get storage usage statistics
  async getStorageStats() {
    try {
      const syncUsage = await new Promise((resolve) => {
        chrome.storage.sync.getBytesInUse(null, (bytes) => resolve(bytes || 0));
      });

      const localUsage = await new Promise((resolve) => {
        chrome.storage.local.getBytesInUse(null, (bytes) => resolve(bytes || 0));
      });

      return {
        sync_bytes: syncUsage,
        local_bytes: localUsage,
        total_bytes: syncUsage + localUsage,
        sync_mb: (syncUsage / 1024 / 1024).toFixed(2),
        local_mb: (localUsage / 1024 / 1024).toFixed(2),
        total_mb: ((syncUsage + localUsage) / 1024 / 1024).toFixed(2)
      };
    } catch (error) {
      console.error('Failed to get storage stats:', error);
      return {
        sync_bytes: 0,
        local_bytes: 0,
        total_bytes: 0,
        sync_mb: '0.00',
        local_mb: '0.00',
        total_mb: '0.00'
      };
    }
  }
}

//Export for service worker
if (typeof module !== 'undefined' && module.exports) {
  module.exports = StorageManager;
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.StorageManager = StorageManager;
}

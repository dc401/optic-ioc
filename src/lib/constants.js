//Optic IOC - Core Constants
//Production-ready configuration constants

const OPTIC_CONSTANTS = {
  //Extension metadata
  VERSION: '1.0.0',
  NAME: 'Optic IOC',

  //Storage keys
  STORAGE_KEYS: {
    CONFIG: 'optic_config',
    ENCRYPTED_SECRETS: 'optic_encrypted_secrets',
    CACHE: 'optic_cache',
    CACHE_META: 'optic_cache_metadata',
    LAST_SYNC: 'optic_last_sync'
  },

  //Encryption settings
  CRYPTO: {
    ALGORITHM: 'AES-GCM',
    KEY_LENGTH: 256,
    IV_LENGTH: 12, //96 bits for GCM
    SALT_LENGTH: 16, //128 bits
    PBKDF2_ITERATIONS: 100000,
    TAG_LENGTH: 128 //GCM auth tag
  },

  //Performance limits
  PERFORMANCE: {
    MAX_CONCURRENT_REQUESTS: 3,
    DEBOUNCE_MS: 500,
    CACHE_TTL_DAYS: 30,
    CACHE_MAX_SIZE_MB: 50,
    MEMORY_CHECK_INTERVAL_MS: 60000, //1min
    IDLE_TIMEOUT_MS: 300000, //5min
    MAX_CHUNK_SIZE_TOKENS: 8000,
    CHUNK_OVERLAP_TOKENS: 200
  },

  //Rate limiting defaults
  RATE_LIMITS: {
    GTI: { requests_per_minute: 4, burst: 10 },
    SHODAN: { requests_per_minute: 1, burst: 1 },
    OTX: { requests_per_minute: 10, burst: 20 },
    URLSCAN: { requests_per_minute: 2, burst: 5 },
    GEMINI: { requests_per_minute: 60, burst: 100 },
    INTERNAL: { requests_per_minute: 60, burst: 100 }
  },

  //IOC type definitions
  IOC_TYPES: {
    IPV4: 'ip',
    IPV6: 'ipv6',
    DOMAIN: 'domain',
    URL: 'url',
    HASH_MD5: 'hash_md5',
    HASH_SHA1: 'hash_sha1',
    HASH_SHA256: 'hash_sha256',
    HASH_GENERIC: 'hash',
    CVE: 'cve',
    EMAIL: 'email'
  },

  //Severity levels
  SEVERITY: {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info',
    UNKNOWN: 'unknown'
  },

  //Default highlight colors (dark mode first)
  HIGHLIGHT_STYLES: {
    critical: {
      color: '#ff0000',
      opacity: 0.3,
      border: '2px solid #cc0000',
      textColor: '#ffffff'
    },
    high: {
      color: '#ff8800',
      opacity: 0.25,
      border: '1px solid #cc6600',
      textColor: '#ffffff'
    },
    medium: {
      color: '#ffff00',
      opacity: 0.2,
      border: '1px dashed #cccc00',
      textColor: '#000000'
    },
    low: {
      color: '#0088ff',
      opacity: 0.15,
      border: 'none',
      textColor: '#ffffff'
    },
    info: {
      color: '#888888',
      opacity: 0.1,
      border: 'none',
      textColor: '#ffffff'
    }
  },

  //Error messages
  ERRORS: {
    API_KEY_MISSING: 'API key not configured for {source}.',
    API_KEY_INVALID: 'Invalid API key for {source}.',
    RATE_LIMIT: 'Rate limit exceeded for {source}. Try again later.',
    NETWORK_ERROR: 'Network error. Check your connection.',
    STORAGE_QUOTA: 'Storage quota exceeded. Clear cache in settings.',
    ENCRYPTION_FAILED: 'Failed to encrypt data.',
    DECRYPTION_FAILED: 'Failed to decrypt data. Try re-entering API keys.',
    INVALID_CONFIG: 'Invalid configuration. Reset to defaults.',
    GEMINI_ERROR: 'Gemini API error: {details}',
    GTI_ERROR: 'GTI API error: {details}'
  },

  //Context menu IDs
  CONTEXT_MENU: {
    ROOT: 'optic_ioc_root',
    PREFIX: 'optic_pivot_'
  },

  //CSS class names
  CSS_CLASSES: {
    HIGHLIGHT: 'optic-highlight',
    TOOLTIP: 'optic-tooltip',
    PANEL: 'optic-panel',
    LOADING: 'optic-loading',
    ERROR: 'optic-error'
  },

  //Message action types (prevent stringly-typed bugs)
  MESSAGE_ACTIONS: {
    CONFIG_GET: 'config.get',
    CONFIG_SAVE: 'config.save',
    PAGE_REFRESH: 'page.refresh',
    PAGE_GET_STATS: 'page.getStats',
    PAGE_ANALYZE: 'page.analyze',
    API_HEALTH_ALERT: 'api.healthAlert',
    DOMAIN_TOGGLE: 'domain.toggle',
    SECURITY_ATTACK_DETECTED: 'security.attackDetected',
    IOC_EXTRACT: 'ioc.extract',
    IOC_ENRICH: 'ioc.enrich',
    IOC_ENRICH_BATCH: 'ioc.enrichBatch',
    IOC_AGGREGATE_SUMMARY: 'ioc.aggregateSummary',
    CONTEXT_UPDATE: 'context.update',
    GET_CLICKED_IOC: 'getClickedIOC'
  },

  //Z-index layering for UI panels
  Z_INDEX: {
    SECURITY_ALERT: 99999999,
    PROGRESS: 9999999,
    PANEL: 9999999, //default for UIPanelBuilder
    FINDINGS: 999998,
    SUMMARY: 999997,
    NOTIFICATION: 999996
  },

  //API endpoints (templates)
  API_ENDPOINTS: {
    GTI: 'https://www.virustotal.com/api/v3',
    SHODAN: 'https://api.shodan.io',
    OTX: 'https://otx.alienvault.com/api/v1',
    URLSCAN: 'https://urlscan.io/api/v1'
  }
};

//Export for use in modules and content scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = OPTIC_CONSTANTS;
}

//Make globally available for service worker and content scripts
if (typeof self !== 'undefined') {
  self.OPTIC_CONSTANTS = OPTIC_CONSTANTS;
}

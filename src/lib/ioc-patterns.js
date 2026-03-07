//Optic IOC - IOC Detection Patterns
//Production-ready regex patterns for detecting indicators of compromise

const IOC_PATTERNS = {
  //IPv4 address (strict)
  IPV4: {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    type: OPTIC_CONSTANTS.IOC_TYPES.IPV4,
    validate: (value) => {
      const parts = value.split('.');
      if (parts.length !== 4) return false;

      const octets = parts.map(p => parseInt(p));
      const [first, second] = octets;

      //Exclude private/reserved/special ranges per RFC
      if (first === 0) return false; //0.0.0.0/8 - "This network"
      if (first === 10) return false; //10.0.0.0/8 - RFC1918 private
      if (first === 127) return false; //127.0.0.0/8 - Loopback
      if (first === 169 && second === 254) return false; //169.254.0.0/16 - Link-local (APIPA)
      if (first === 172 && second >= 16 && second <= 31) return false; //172.16.0.0/12 - RFC1918 private
      if (first === 192 && second === 168) return false; //192.168.0.0/16 - RFC1918 private
      if (first >= 224 && first <= 239) return false; //224.0.0.0/4 - Multicast
      if (first >= 240) return false; //240.0.0.0/4 - Reserved

      return true;
    }
  },

  //IPv6 address (simplified)
  IPV6: {
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g,
    type: OPTIC_CONSTANTS.IOC_TYPES.IPV6,
    validate: (value) => {
      const lower = value.toLowerCase();

      //Exclude special/private/local IPv6 ranges
      if (lower === '::1') return false; //Loopback
      if (lower === '::') return false; //Unspecified
      if (lower.startsWith('fe80:')) return false; //Link-local fe80::/10
      if (lower.startsWith('feb') || lower.startsWith('fea') || lower.startsWith('fe9') || lower.startsWith('fe8')) return false; //Link-local expanded
      if (lower.startsWith('fc') || lower.startsWith('fd')) return false; //Unique local fc00::/7
      if (lower.startsWith('ff')) return false; //Multicast ff00::/8

      return true;
    }
  },

  //Domain name (strict, requires TLD)
  DOMAIN: {
    pattern: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.DOMAIN,
    validate: (value) => {
      value = value.toLowerCase();
      //Exclude localhost and common non-suspicious domains
      if (value === 'localhost') return false;
      //Must have at least one dot
      if (!value.includes('.')) return false;
      //Check TLD length (2-20 chars)
      const tld = value.split('.').pop();
      if (tld.length < 2 || tld.length > 20) return false;
      return true;
    }
  },

  //URL (http/https/ftp)
  URL: {
    pattern: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`\[\]]+/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.URL,
    validate: (value) => {
      try {
        const url = new URL(value);
        const hostname = url.hostname.toLowerCase();

        //Exclude localhost/loopback
        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return false;

        //Exclude private IPv4 in URLs
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
          const parts = hostname.split('.');
          const octets = parts.map(p => parseInt(p));
          const [first, second] = octets;

          if (first === 10) return false; //10.0.0.0/8
          if (first === 172 && second >= 16 && second <= 31) return false; //172.16.0.0/12
          if (first === 192 && second === 168) return false; //192.168.0.0/16
          if (first === 169 && second === 254) return false; //169.254.0.0/16
          if (first === 0 || first === 127 || first >= 224) return false; //reserved/multicast
        }

        //Exclude private IPv6 in URLs
        if (hostname.includes(':')) {
          if (hostname.startsWith('fe80:') || hostname.startsWith('fc') || hostname.startsWith('fd') || hostname.startsWith('ff')) return false;
        }

        return true;
      } catch {
        return false;
      }
    }
  },

  //MD5 hash
  MD5: {
    pattern: /\b[a-f0-9]{32}\b/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.HASH_MD5,
    validate: (value) => {
      return /^[a-f0-9]{32}$/i.test(value);
    }
  },

  //SHA1 hash
  SHA1: {
    pattern: /\b[a-f0-9]{40}\b/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA1,
    validate: (value) => {
      return /^[a-f0-9]{40}$/i.test(value);
    }
  },

  //SHA256 hash
  SHA256: {
    pattern: /\b[a-f0-9]{64}\b/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA256,
    validate: (value) => {
      return /^[a-f0-9]{64}$/i.test(value);
    }
  },

  //CVE ID
  CVE: {
    pattern: /\bCVE-\d{4}-\d{4,7}\b/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.CVE,
    validate: (value) => {
      return /^CVE-\d{4}-\d{4,7}$/i.test(value);
    }
  },

  //Email address
  EMAIL: {
    pattern: /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
    type: OPTIC_CONSTANTS.IOC_TYPES.EMAIL,
    validate: (value) => {
      //Basic validation
      return value.includes('@') && value.includes('.');
    }
  }
};

//Extract all IOCs from text (handles both normal and defanged IOCs)
function extractIOCs(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const found = [];
  const seen = new Set(); //dedupe

  //FIXED: Truncate BEFORE refanging to optimize performance
  const MAX_INPUT = 500000;
  if (text.length > MAX_INPUT) {
    console.warn(`[IOC-EXTRACT] Truncating input from ${text.length} to ${MAX_INPUT} chars`);
    text = text.substring(0, MAX_INPUT);
  }

  //Preprocess: refang text to restore defanged IOCs
  const refangedText = refangIOC(text);

  //Try each pattern on refanged text
  for (const [name, config] of Object.entries(IOC_PATTERNS)) {
    const matches = refangedText.matchAll(config.pattern);

    for (const match of matches) {
      const value = match[0];

      //Validate
      if (!config.validate || config.validate(value)) {
        //Dedupe
        const key = `${config.type}:${value.toLowerCase()}`;
        if (!seen.has(key)) {
          seen.add(key);
          found.push({
            type: config.type,
            value: value,
            start: match.index,
            end: match.index + value.length,
            was_defanged: text !== refangedText //flag if original was defanged
          });
        }
      }
    }
  }

  //Sort by position in text
  found.sort((a, b) => a.start - b.start);

  return found;
}

//REMOVED: detectHashType and validateIOC (duplicates of url-builder and security-validator versions)

//Defang IOC (make safe for display/copy)
function defangIOC(value, type) {
  if (!value) return value;

  switch (type) {
    case OPTIC_CONSTANTS.IOC_TYPES.IPV4:
    case OPTIC_CONSTANTS.IOC_TYPES.IPV6:
      return value.replace(/\./g, '[.]');

    case OPTIC_CONSTANTS.IOC_TYPES.DOMAIN:
      return value.replace(/\./g, '[.]');

    case OPTIC_CONSTANTS.IOC_TYPES.URL:
      return value.replace(/\./g, '[.]').replace(/:/g, '[:]');

    case OPTIC_CONSTANTS.IOC_TYPES.EMAIL:
      return value.replace(/@/g, '[@]').replace(/\./g, '[.]');

    default:
      return value;
  }
}

//Refang IOC (restore to original from defanged format)
function refangIOC(value) {
  if (!value) return value;
  return value
    //Brackets
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[@\]/g, '@')
    .replace(/\[\/\/\]/g, '//')
    .replace(/\[dot\]/gi, '.')
    //Parentheses
    .replace(/\(dot\)/gi, '.')
    .replace(/\(at\)/gi, '@')
    .replace(/\(\.\)/g, '.')
    //hxxp variants
    .replace(/hxxp/gi, 'http')
    .replace(/hXXp/g, 'http')
    .replace(/h\[tt\]p/gi, 'http')
    .replace(/h\[xx\]p/gi, 'http')
    .replace(/h__p/gi, 'http')
    //Common defang patterns
    .replace(/\[http\]/gi, 'http')
    .replace(/\[https\]/gi, 'https')
    .replace(/\s*DOT\s*/gi, '.')
    .replace(/\s*AT\s*/gi, '@')
    .replace(/\s+dot\s+/gi, '.')
    .replace(/\s+at\s+/gi, '@')
    //Underscores used for defanging
    .replace(/(\d+)_(\d+)_(\d+)_(\d+)/g, '$1.$2.$3.$4') //IP with underscores
    //Spaces in URLs
    .replace(/h\s*t\s*t\s*p\s*:/gi, 'http:')
    .replace(/\\{2,}/g, '\\'); //fix escaped backslashes
}

//Export functions (for both Node.js and browser globals)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    IOC_PATTERNS,
    extractIOCs,
    defangIOC,
    refangIOC
  };
}

//Make functions globally available for service worker
if (typeof self !== 'undefined') {
  self.IOC_PATTERNS = IOC_PATTERNS;
  self.extractIOCs = extractIOCs;
  self.defangIOC = defangIOC;
  self.refangIOC = refangIOC;
}

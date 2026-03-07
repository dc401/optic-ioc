//Optic IOC - URL Template Builder
//Builds pivot link URLs from templates with placeholder replacement

class URLBuilder {
  constructor() {
    this.defaultConfig = null;
  }

  //Set default config (target org, etc.)
  setConfig(config) {
    this.defaultConfig = config;
  }

  //Build URL from template
  //template: URL string with {{placeholders}}
  //iocType: type of IOC (ip, domain, hash_md5, etc.)
  //iocValue: actual IOC value
  //typeMapping: optional type mapping object
  buildURL(template, iocType, iocValue, typeMapping = null) {
    if (!template || !iocValue) {
      return null;
    }

    try {
      //Detect specific hash type if generic "hash"
      let specificType = iocType;
      if (iocType === OPTIC_CONSTANTS.IOC_TYPES.HASH_GENERIC) {
        specificType = this.detectHashType(iocValue);
      }

      //Build placeholder values
      const placeholders = this.buildPlaceholders(specificType, iocValue, typeMapping);

      //Replace all placeholders
      let url = template;
      for (const [key, value] of Object.entries(placeholders)) {
        url = url.replace(new RegExp(`{{${key}}}`, 'g'), value);
      }

      //Validate URL
      if (!this.isValidURL(url)) {
        console.error('Invalid URL generated:', url);
        return null;
      }

      return url;
    } catch (error) {
      console.error('URL build error:', error);
      return null;
    }
  }

  //Build all placeholder values
  buildPlaceholders(iocType, iocValue, typeMapping) {
    const placeholders = {
      //Basic
      value: iocValue,
      value_encoded: encodeURIComponent(iocValue),
      value_lower: iocValue.toLowerCase(),
      value_upper: iocValue.toUpperCase(),
      type: iocType,

      //Timestamp
      timestamp: Date.now(),
      timestamp_sec: Math.floor(Date.now() / 1000),

      //Organization (from config)
      org: this.defaultConfig?.target_org || '',
      org_encoded: encodeURIComponent(this.defaultConfig?.target_org || ''),
      org_domain: this.extractDomain(this.defaultConfig?.target_org || '')
    };

    //Add type mappings if provided
    if (typeMapping) {
      //GTI type mapping
      if (typeMapping.ip && (iocType === OPTIC_CONSTANTS.IOC_TYPES.IPV4 || iocType === OPTIC_CONSTANTS.IOC_TYPES.IPV6)) {
        placeholders.gti_type = typeMapping.ip;
      } else if (typeMapping[iocType]) {
        placeholders.gti_type = typeMapping[iocType];
      } else {
        placeholders.gti_type = iocType;
      }

      //OTX type mapping (more specific)
      placeholders.otx_type = typeMapping[iocType] || iocType;
    } else {
      //Default mappings
      placeholders.gti_type = this.getGTIType(iocType);
      placeholders.otx_type = this.getOTXType(iocType);
    }

    return placeholders;
  }

  //Detect hash type from value
  detectHashType(value) {
    if (!value) return OPTIC_CONSTANTS.IOC_TYPES.HASH_GENERIC;

    const cleaned = value.toLowerCase().trim();

    if (/^[a-f0-9]{32}$/.test(cleaned)) {
      return OPTIC_CONSTANTS.IOC_TYPES.HASH_MD5;
    } else if (/^[a-f0-9]{40}$/.test(cleaned)) {
      return OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA1;
    } else if (/^[a-f0-9]{64}$/.test(cleaned)) {
      return OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA256;
    }

    return OPTIC_CONSTANTS.IOC_TYPES.HASH_GENERIC;
  }

  //Get GTI-specific type string
  getGTIType(iocType) {
    const mapping = {
      [OPTIC_CONSTANTS.IOC_TYPES.IPV4]: 'ip-address',
      [OPTIC_CONSTANTS.IOC_TYPES.IPV6]: 'ip-address',
      [OPTIC_CONSTANTS.IOC_TYPES.DOMAIN]: 'domain',
      [OPTIC_CONSTANTS.IOC_TYPES.URL]: 'url',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_MD5]: 'file',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA1]: 'file',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA256]: 'file',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_GENERIC]: 'file'
    };
    return mapping[iocType] || iocType;
  }

  //Get OTX-specific type string
  getOTXType(iocType) {
    const mapping = {
      [OPTIC_CONSTANTS.IOC_TYPES.IPV4]: 'IPv4',
      [OPTIC_CONSTANTS.IOC_TYPES.IPV6]: 'IPv6',
      [OPTIC_CONSTANTS.IOC_TYPES.DOMAIN]: 'domain',
      [OPTIC_CONSTANTS.IOC_TYPES.URL]: 'url',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_MD5]: 'FileHash-MD5',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA1]: 'FileHash-SHA1',
      [OPTIC_CONSTANTS.IOC_TYPES.HASH_SHA256]: 'FileHash-SHA256',
      [OPTIC_CONSTANTS.IOC_TYPES.CVE]: 'CVE',
      [OPTIC_CONSTANTS.IOC_TYPES.EMAIL]: 'email'
    };
    return mapping[iocType] || iocType;
  }

  //Extract domain from string (if present)
  extractDomain(str) {
    if (!str) return '';

    //Check if string is already a domain
    const domainPattern = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/i;
    const match = str.match(domainPattern);

    return match ? match[0] : '';
  }

  //Validate URL
  isValidURL(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  //Check if pivot link supports IOC type
  isPivotSupported(pivotConfig, iocType) {
    if (!pivotConfig || !pivotConfig.ioc_types) {
      return false;
    }

    //Generic hash support
    if (iocType.startsWith('hash_') && pivotConfig.ioc_types.includes('hash')) {
      return true;
    }

    return pivotConfig.ioc_types.includes(iocType);
  }

  //Build multiple pivot URLs for an IOC
  buildPivotURLs(ioc, pivotConfigs) {
    if (!ioc || !ioc.value || !ioc.type) {
      return [];
    }

    const urls = [];

    for (const [id, config] of Object.entries(pivotConfigs)) {
      if (!config.enabled) continue;
      if (!this.isPivotSupported(config, ioc.type)) continue;

      const url = this.buildURL(
        config.url_template,
        ioc.type,
        ioc.value,
        config.type_mapping
      );

      if (url) {
        urls.push({
          id: id,
          label: config.label,
          url: url,
          order: config.order || 999
        });
      }
    }

    //Sort by order
    urls.sort((a, b) => a.order - b.order);

    return urls;
  }
}

//Export singleton
const urlBuilder = new URLBuilder();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = urlBuilder;
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.urlBuilder = urlBuilder;
  self.URLBuilder = URLBuilder;
}

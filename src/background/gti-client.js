//Optic IOC - GTI (Google Threat Intelligence) API Client
//VirusTotal API v3 integration
//Provides threat intelligence lookups for IPs, domains, hashes, URLs

class GTIClient {
  constructor(storageManager) {
    this.storage = storageManager;
    this.apiKey = null;
    this.baseUrl = 'https://www.virustotal.com/api/v3';
    this.maxRetries = 5;
    this.maxBackoff = 64; //seconds
  }

  //Exponential backoff with jitter helper
  //FIXED: Don't retry auth errors (401, 403)
  async exponentialBackoff(fn, retryableErrors = [429, 500, 502, 503, 504]) {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        //FIXED: Never retry auth errors - fail fast
        const isAuthError = error.status && (error.status === 401 || error.status === 403);
        if (isAuthError) {
          console.error('[GTI] Auth error - check API key');
          throw error;
        }

        //Check if error is retryable
        const isRetryable = error.status && retryableErrors.includes(error.status);
        const isLastAttempt = attempt === this.maxRetries - 1;

        if (!isRetryable || isLastAttempt) {
          throw error; //not retryable or max retries reached
        }

        //Calculate wait time with jitter: min((2^n + random), maxBackoff)
        const baseDelay = Math.pow(2, attempt);
        const jitter = Math.random(); //0 to 1
        const delay = Math.min(baseDelay + jitter, this.maxBackoff);

        console.log(`GTI API retry ${attempt + 1}/${this.maxRetries} after ${delay.toFixed(2)}s (error ${error.status})`);

        //Wait before retry
        await new Promise(resolve => setTimeout(resolve, delay * 1000));
      }
    }
  }

  //Initialize with API key
  async initialize() {
    try {
      const secrets = await this.storage.loadSecrets();
      this.apiKey = secrets?.gti_api_key;
      return !!this.apiKey;
    } catch (error) {
      console.error('Failed to load GTI API key:', error);
      return false;
    }
  }

  //Lookup an IOC
  async lookup(iocType, iocValue) {
    if (!this.apiKey) {
      await this.initialize();
      if (!this.apiKey) {
        throw new Error('GTI API key not configured');
      }
    }

    //Route to appropriate endpoint based on IOC type
    switch (iocType) {
      case 'ip':
      case 'ipv4':
      case 'ipv6':
        return await this.lookupIP(iocValue);

      case 'domain':
        return await this.lookupDomain(iocValue);

      case 'url':
        return await this.lookupURL(iocValue);

      case 'hash_md5':
      case 'hash_sha1':
      case 'hash_sha256':
      case 'hash':
        return await this.lookupFileHash(iocValue);

      default:
        throw new Error(`Unsupported IOC type for GTI: ${iocType}`);
    }
  }

  //Lookup IP address
  async lookupIP(ip) {
    const url = `${this.baseUrl}/ip_addresses/${ip}`;
    return await this.makeRequest(url);
  }

  //Lookup domain
  async lookupDomain(domain) {
    const url = `${this.baseUrl}/domains/${domain}`;
    return await this.makeRequest(url);
  }

  //Lookup URL
  async lookupURL(urlToCheck) {
    //URLs need to be base64 encoded (URL-safe, no padding)
    const urlId = btoa(urlToCheck)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const url = `${this.baseUrl}/urls/${urlId}`;
    return await this.makeRequest(url);
  }

  //Lookup file hash
  async lookupFileHash(hash) {
    const url = `${this.baseUrl}/files/${hash}`;
    return await this.makeRequest(url);
  }

  //Make API request to GTI with exponential backoff
  async makeRequest(url) {
    return await this.exponentialBackoff(async () => {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey,
          'Accept': 'application/json'
        }
      });

      if (response.status === 404) {
        //Not found in GTI database - not necessarily an error
        return {
          data: {
            attributes: {
              last_analysis_stats: {
                harmless: 0,
                malicious: 0,
                suspicious: 0,
                undetected: 0,
                timeout: 0
              },
              reputation: 0
            }
          },
          not_found: true
        };
      }

      if (!response.ok) {
        const errorText = await response.text();
        const error = new Error(`GTI API error: ${response.status} - ${errorText}`);
        error.status = response.status; //attach status for retry logic
        throw error;
      }

      const data = await response.json();
      return data;
    });
  }

  //Test API key
  async testConnection() {
    try {
      await this.initialize();
      if (!this.apiKey) {
        return { valid: false, error: 'API key not configured' };
      }

      //Test with a known-good IP (Google DNS)
      const url = `${this.baseUrl}/ip_addresses/8.8.8.8`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey,
          'Accept': 'application/json'
        }
      });

      if (response.ok) {
        return {
          valid: true,
          message: 'GTI API connection successful',
          status: response.status
        };
      } else {
        const errorText = await response.text();
        return {
          valid: false,
          error: `HTTP ${response.status}: ${errorText}`,
          status: response.status
        };
      }
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }

  //Get threat summary from GTI response
  getThreatSummary(gtiData) {
    if (!gtiData || !gtiData.data || !gtiData.data.attributes) {
      return 'No threat data available';
    }

    const attrs = gtiData.data.attributes;
    const stats = attrs.last_analysis_stats;

    if (!stats) {
      return 'No analysis data';
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    if (malicious === 0 && suspicious === 0) {
      return 'Clean - No threats detected';
    }

    if (malicious > 30) {
      return `Critical threat - ${malicious}/${total} vendors flagged as malicious`;
    }

    if (malicious > 10) {
      return `High threat - ${malicious}/${total} vendors flagged as malicious`;
    }

    if (malicious > 0 || suspicious > 5) {
      return `Suspicious - ${malicious} malicious, ${suspicious} suspicious detections`;
    }

    return `Low risk - ${suspicious} suspicious detections`;
  }
}

//Export class (singleton will be created by service worker)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { GTIClient };
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.GTIClient = GTIClient;
}

//Optic IOC - API Orchestrator
//Coordinates parallel API requests to Gemini and GTI
//Handles caching, rate limiting, and result aggregation

class APIOrchestrator {
  constructor(storageManager, cacheManager, rateLimiterManager) {
    this.storage = storageManager;
    this.cache = cacheManager;
    this.rateLimiter = rateLimiterManager;
    this.geminiClient = null;
    this.gtiClient = null;
  }

  //Initialize with API clients
  initialize(geminiClient, gtiClient) {
    this.geminiClient = geminiClient;
    this.gtiClient = gtiClient;
  }

  //Enrich a single IOC
  //SECURITY: Validates IOC values to prevent injection attacks (OWASP A03)
  async enrichIOC(iocType, iocValue, targetOrg = '') {
    try {
      //SECURITY: Validate IOC value before processing
      const validation = securityValidator.validateIOCValue(iocType, iocValue);
      if (!validation.valid) {
        console.warn(`[SECURITY] Invalid IOC rejected: ${iocType} ${iocValue} - ${validation.reason}`);
        securityValidator.logSecurityEvent('invalid_ioc', {
          ioc_type: iocType,
          ioc_value: iocValue.substring(0, 100), //truncate for logging
          reason: validation.reason,
          patterns: validation.patterns
        });
        return this.getErrorEnrichment(iocType, iocValue, new Error('Invalid IOC value: ' + validation.reason));
      }

      //Check cache first
      const cached = await this.cache.get(iocType, iocValue);
      if (cached) {
        console.log(`Cache hit for ${iocType}: ${iocValue}`);
        return cached;
      }

      //Fetch from APIs in parallel
      const results = await this.fetchFromAPIs(iocType, iocValue, targetOrg);

      //Calculate severity score
      const enrichment = this.aggregateResults(results, iocType, iocValue, targetOrg);

      //Cache the result
      await this.cache.set(iocType, iocValue, enrichment);

      return enrichment;
    } catch (error) {
      console.error(`Failed to enrich ${iocType} ${iocValue}:`, error);
      return this.getErrorEnrichment(iocType, iocValue, error);
    }
  }

  //Fetch data from all available APIs (SEQUENTIAL with rate limiting)
  //FIXED: GTI must complete before Gemini to provide context
  //FIXED: Apply rate limiting to prevent quota exhaustion
  async fetchFromAPIs(iocType, iocValue, targetOrg) {
    const results = {};

    //STEP 1: GTI lookup (rate-limited)
    if (this.gtiClient) {
      try {
        results.gti = await this.rateLimiter.execute(
          'gti',
          OPTIC_CONSTANTS.RATE_LIMITS.GTI,
          () => this.gtiClient.lookup(iocType, iocValue)
        );
      } catch (err) {
        console.error('GTI lookup failed:', err);
        results.gti = { error: err.message };
      }
    }

    //STEP 2: Gemini analysis with GTI context (rate-limited)
    if (this.geminiClient) {
      try {
        results.gemini = await this.rateLimiter.execute(
          'gemini',
          OPTIC_CONSTANTS.RATE_LIMITS.GEMINI,
          () => this.geminiClient.analyze(iocType, iocValue, targetOrg, results.gti)
        );
      } catch (err) {
        console.error('Gemini analysis failed:', err);
        results.gemini = { error: err.message };
      }
    }

    return results;
  }

  //Aggregate results from multiple sources
  aggregateResults(results, iocType, iocValue, targetOrg) {
    const enrichment = {
      ioc_type: iocType,
      ioc_value: iocValue,
      target_org: targetOrg,
      timestamp: Date.now(),
      sources: {},
      severity: 'unknown',
      severity_score: 0,
      summary: '',
      details: {}
    };

    //Process GTI results
    if (results.gti && !results.gti.error) {
      enrichment.sources.gti = results.gti;
      enrichment.details.gti_stats = this.extractGTIStats(results.gti);
    }

    //Process Gemini results
    if (results.gemini && !results.gemini.error) {
      enrichment.sources.gemini = results.gemini;
      enrichment.summary = results.gemini.summary || '';
      enrichment.details.ai_analysis = results.gemini.analysis || '';
    }

    //Calculate overall severity
    enrichment.severity = this.calculateSeverity(results);
    enrichment.severity_score = this.calculateSeverityScore(results);

    return enrichment;
  }

  //Extract key stats from GTI response
  extractGTIStats(gtiData) {
    if (!gtiData || !gtiData.data || !gtiData.data.attributes) {
      return null;
    }

    const attrs = gtiData.data.attributes;
    const stats = attrs.last_analysis_stats || {};

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: Object.values(stats).reduce((a, b) => a + b, 0),
      reputation: attrs.reputation || 0,
      categories: attrs.categories || {},
      last_analysis_date: attrs.last_analysis_date
    };
  }

  //Calculate severity level from API results
  calculateSeverity(results) {
    const score = this.calculateSeverityScore(results);

    const { CRITICAL, HIGH, MEDIUM, LOW, INFO } = OPTIC_CONSTANTS.SEVERITY;
    if (score >= 80) return CRITICAL;
    if (score >= 60) return HIGH;
    if (score >= 40) return MEDIUM;
    if (score >= 20) return LOW;
    return INFO; //clean/safe
  }

  //Calculate numeric severity score (0-100)
  calculateSeverityScore(results) {
    let score = 0;

    //GTI-based scoring
    if (results.gti && results.gti.data) {
      const stats = results.gti.data.attributes?.last_analysis_stats;
      if (stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);

        if (total > 0) {
          //Score based on detection ratio
          const detectionRatio = (malicious + suspicious * 0.5) / total;
          score = Math.max(score, detectionRatio * 100);
        }

        //Boost score for high malicious count
        if (malicious > 10) score = Math.max(score, 70);
        if (malicious > 30) score = Math.max(score, 90);
      }

      //Check reputation (VirusTotal reputation scale: -100 to +100)
      const reputation = results.gti.data.attributes?.reputation;
      if (reputation !== undefined && reputation < 0) {
        //Negative reputation increases score
        score = Math.max(score, Math.abs(reputation));
      }
    }

    //Gemini-based scoring (if available)
    if (results.gemini && results.gemini.severity_score) {
      score = Math.max(score, results.gemini.severity_score);
    }

    return Math.min(100, Math.round(score));
  }

  //Return error enrichment data
  getErrorEnrichment(iocType, iocValue, error) {
    return {
      ioc_type: iocType,
      ioc_value: iocValue,
      timestamp: Date.now(),
      severity: 'unknown',
      severity_score: 0,
      summary: 'Enrichment failed',
      error: error.message,
      sources: {},
      details: {}
    };
  }

  //Batch enrich multiple IOCs
  async enrichBatch(iocs, targetOrg = '') {
    const results = {};

    //Process in batches to avoid overwhelming APIs
    const batchSize = 5;
    for (let i = 0; i < iocs.length; i += batchSize) {
      const batch = iocs.slice(i, i + batchSize);
      const promises = batch.map(ioc =>
        this.enrichIOC(ioc.type, ioc.value, targetOrg)
          .then(result => {
            results[`${ioc.type}:${ioc.value}`] = result;
          })
      );

      await Promise.all(promises);

      //Small delay between batches
      if (i + batchSize < iocs.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    return results;
  }
}

//Export class (singleton will be created by service worker)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { APIOrchestrator };
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.APIOrchestrator = APIOrchestrator;
}

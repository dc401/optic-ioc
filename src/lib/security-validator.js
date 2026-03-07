//Optic IOC - Security Validator
//OWASP Top 10 + LLM Top 10 security validations
//Prevents prompt injection, secret leakage, injection attacks

class SecurityValidator {
  constructor() {
    //Prompt injection patterns (OWASP LLM01)
    this.promptInjectionPatterns = [
      /ignore\s+(all\s+)?previous\s+instructions?/i,
      /disregard\s+(all\s+)?previous/i,
      /forget\s+(everything|all|previous)/i,
      /you\s+are\s+now\s+(a|an|the)/i, //role-play injection
      /new\s+instructions?:/i,
      /system\s*:\s*/i, //trying to inject system messages
      /assistant\s*:\s*/i,
      /\[INST\]/i, //Llama-style injection
      /\<\|im_start\|\>/i, //ChatML injection
      /<system>/i,
      /<\/system>/i,
      /respond\s+with\s+(only|just)/i,
      /from\s+now\s+on/i,
      /instead\s+of/i,
      /do\s+not\s+(follow|obey)/i,
      /DAN\s+mode/i, //"Do Anything Now"
      /developer\s+mode/i,
      /jailbreak/i
    ];

    //Secret patterns (OWASP LLM06, A02 Crypto Failures)
    this.secretPatterns = {
      aws_key: /AKIA[0-9A-Z]{16}/,
      aws_secret: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[A-Za-z0-9/+=]{40}/,
      github_token: /gh[ps]_[A-Za-z0-9]{36,}/,
      openai_key: /sk-[A-Za-z0-9]{48}/,
      google_api_key: /AIza[A-Za-z0-9_-]{35}/,
      slack_token: /xox[baprs]-[A-Za-z0-9-]{10,72}/,
      stripe_key: /sk_live_[A-Za-z0-9]{24,}/,
      jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
      private_key: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
      password_field: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i,
      api_key_generic: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/i,
      bearer_token: /Bearer\s+[A-Za-z0-9_-]{20,}/
    };

    //XSS patterns (OWASP A03 Injection)
    this.xssPatterns = [
      /<script[\s>]/i,
      /<iframe[\s>]/i,
      /<object[\s>]/i,
      /<embed[\s>]/i,
      /javascript\s*:/i,
      /on\w+\s*=/i, //event handlers
      /data:text\/html/i,
      /vbscript:/i,
      /<svg[\s>].*on/i, //SVG with events
      /expression\s*\(/i, //CSS expression
      /import\s*\(/i //dynamic import
    ];

    //SQL injection patterns (defense in depth - not used in extension but good practice)
    this.sqlPatterns = [
      /'\s*(or|and)\s+['"]?\d/i,
      /union\s+select/i,
      /;\s*drop\s+table/i,
      /;\s*delete\s+from/i,
      /benchmark\s*\(/i,
      /sleep\s*\(/i,
      /waitfor\s+delay/i
    ];
  }

  //Detect prompt injection attempts (OWASP LLM01)
  detectPromptInjection(text) {
    if (!text || typeof text !== 'string') {
      return { detected: false, confidence: 0 };
    }

    const matches = [];
    let confidence = 0;

    for (const pattern of this.promptInjectionPatterns) {
      if (pattern.test(text)) {
        matches.push(pattern.source);
        confidence += 10; //each match increases confidence
      }
    }

    //Multi-language check (Unicode tricks)
    if (/[\u200B-\u200D\uFEFF]/.test(text)) {
      matches.push('zero-width characters (potential obfuscation)');
      confidence += 5;
    }

    //Excessive delimiters (trying to escape context)
    const delimiterCount = (text.match(/[<>{}[\]]/g) || []).length;
    if (delimiterCount > 50) {
      matches.push('excessive delimiters');
      confidence += 15;
    }

    //Role-play attempts
    if (/you\s+are\s+(a|an)\s+\w+\s+(that|who)/i.test(text)) {
      matches.push('role-play injection attempt');
      confidence += 20;
    }

    return {
      detected: matches.length > 0,
      confidence: Math.min(confidence, 100),
      patterns: matches,
      recommendation: matches.length > 0 ? 'Potential prompt injection detected - review content before processing' : 'No obvious injection detected'
    };
  }

  //Detect secrets in content (OWASP LLM06, A02)
  detectSecrets(text) {
    if (!text || typeof text !== 'string') {
      return { found: false, secrets: [] };
    }

    const found = [];

    for (const [type, pattern] of Object.entries(this.secretPatterns)) {
      const matches = text.match(pattern);
      if (matches) {
        found.push({
          type: type,
          sample: matches[0].substring(0, 20) + '...', //partial for logging
          position: text.indexOf(matches[0])
        });
      }
    }

    return {
      found: found.length > 0,
      count: found.length,
      types: found.map(s => s.type),
      secrets: found,
      recommendation: found.length > 0 ? 'REDACT secrets before sending to LLM' : 'No secrets detected'
    };
  }

  //Redact secrets from text
  redactSecrets(text) {
    if (!text || typeof text !== 'string') {
      return text;
    }

    let redacted = text;
    let redactionCount = 0;

    for (const [type, pattern] of Object.entries(this.secretPatterns)) {
      const matches = redacted.match(new RegExp(pattern, 'g'));
      if (matches) {
        for (const match of matches) {
          redacted = redacted.replace(match, `[REDACTED_${type.toUpperCase()}]`);
          redactionCount++;
        }
      }
    }

    return {
      text: redacted,
      redacted: redactionCount > 0,
      count: redactionCount
    };
  }

  //Detect XSS attempts (OWASP A03)
  detectXSS(text) {
    if (!text || typeof text !== 'string') {
      return { detected: false };
    }

    const matches = [];

    for (const pattern of this.xssPatterns) {
      if (pattern.test(text)) {
        matches.push(pattern.source);
      }
    }

    return {
      detected: matches.length > 0,
      patterns: matches,
      recommendation: matches.length > 0 ? 'Potential XSS payload detected - sanitize before display' : 'No XSS detected'
    };
  }

  //Validate IOC value (OWASP A03 Injection)
  validateIOCValue(iocType, iocValue) {
    if (!iocValue || typeof iocValue !== 'string') {
      return { valid: false, reason: 'Empty or invalid IOC value' };
    }

    //Length check (prevent DOS and payload injection)
    if (iocValue.length > 512) {
      return { valid: false, reason: 'IOC value too long (max 512 chars)' };
    }

    //Check for XSS in IOC
    const xss = this.detectXSS(iocValue);
    if (xss.detected) {
      return { valid: false, reason: 'IOC contains potential XSS payload', patterns: xss.patterns };
    }

    //Check for SQL injection (defense in depth)
    for (const pattern of this.sqlPatterns) {
      if (pattern.test(iocValue)) {
        return { valid: false, reason: 'IOC contains SQL injection pattern', pattern: pattern.source };
      }
    }

    //Type-specific validation
    switch (iocType) {
      case 'ip':
      case 'ipv4':
        //Basic IPv4 format check
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(iocValue)) {
          return { valid: false, reason: 'Invalid IPv4 format' };
        }
        break;

      case 'domain':
        //Basic domain format check
        if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(iocValue)) {
          return { valid: false, reason: 'Invalid domain format' };
        }
        break;

      case 'hash_md5':
        if (!/^[a-fA-F0-9]{32}$/.test(iocValue)) {
          return { valid: false, reason: 'Invalid MD5 hash format' };
        }
        break;

      case 'hash_sha1':
        if (!/^[a-fA-F0-9]{40}$/.test(iocValue)) {
          return { valid: false, reason: 'Invalid SHA1 hash format' };
        }
        break;

      case 'hash_sha256':
        if (!/^[a-fA-F0-9]{64}$/.test(iocValue)) {
          return { valid: false, reason: 'Invalid SHA256 hash format' };
        }
        break;

      case 'url':
        //Check for dangerous protocols
        if (/^(javascript|data|vbscript|file):/i.test(iocValue)) {
          return { valid: false, reason: 'Dangerous URL protocol' };
        }
        break;

      case 'email':
        //Basic email format
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(iocValue)) {
          return { valid: false, reason: 'Invalid email format' };
        }
        break;
    }

    return { valid: true };
  }

  //Validate LLM JSON response structure (OWASP LLM02)
  validateLLMResponse(response, expectedSchema) {
    if (!response || typeof response !== 'object') {
      return { valid: false, reason: 'Response is not an object' };
    }

    const missing = [];

    for (const field of expectedSchema.required || []) {
      if (!(field in response)) {
        missing.push(field);
      }
    }

    if (missing.length > 0) {
      return { valid: false, reason: 'Missing required fields', missing };
    }

    //Type validation
    for (const [field, expectedType] of Object.entries(expectedSchema.types || {})) {
      if (field in response && typeof response[field] !== expectedType) {
        return { valid: false, reason: `Invalid type for ${field}`, expected: expectedType, got: typeof response[field] };
      }
    }

    //Enum validation
    for (const [field, allowedValues] of Object.entries(expectedSchema.enums || {})) {
      if (field in response && !allowedValues.includes(response[field])) {
        return { valid: false, reason: `Invalid value for ${field}`, allowed: allowedValues, got: response[field] };
      }
    }

    return { valid: true };
  }

  //Sanitize page content before sending to LLM (combine all checks)
  //CTI ANALYST MODE: Log and warn, but DON'T block (analysts NEED to see payloads)
  sanitizeForLLM(pageContent, maxLength = 30000) {
    if (!pageContent) return { safe: true, content: '', warnings: [] };

    const warnings = [];

    //1. Truncate to safe length (OWASP LLM04 - prevent DOS)
    let content = pageContent.length > maxLength ? pageContent.substring(0, maxLength) : pageContent;
    if (pageContent.length > maxLength) {
      warnings.push(`Content truncated from ${pageContent.length} to ${maxLength} chars`);
    }

    //2. Detect prompt injection (LOG ONLY - don't block)
    const injection = this.detectPromptInjection(content);
    if (injection.detected) {
      warnings.push(`Prompt injection detected (confidence: ${injection.confidence}%) - ${injection.patterns.slice(0, 3).join(', ')}`);
    }

    //3. Detect and redact secrets (REDACT to prevent leakage)
    const secretCheck = this.detectSecrets(content);
    if (secretCheck.found) {
      const redacted = this.redactSecrets(content);
      content = redacted.text;
      warnings.push(`Redacted ${redacted.count} secret(s): ${secretCheck.types.join(', ')}`);
    }

    //4. Detect XSS (LOG ONLY - CTI analysts need to see payloads)
    const xss = this.detectXSS(content);
    if (xss.detected) {
      warnings.push(`XSS payloads detected (${xss.patterns.length}) - this is EXPECTED for CTI analysis pages`);
    }

    return {
      safe: true, //Always "safe" for CTI analysts (they handle malicious content professionally)
      content: content,
      warnings: warnings,
      stats: {
        original_length: pageContent.length,
        sanitized_length: content.length,
        secrets_redacted: secretCheck.count || 0,
        injection_confidence: injection.confidence || 0,
        xss_patterns: xss.detected ? xss.patterns.length : 0
      }
    };
  }

  //Log security event (OWASP A09 - Security Logging)
  logSecurityEvent(eventType, details) {
    const event = {
      timestamp: new Date().toISOString(),
      type: eventType,
      details: details,
      severity: this.getEventSeverity(eventType)
    };

    console.warn('[SECURITY]', event);

    //Store in chrome.storage for audit trail
    chrome.storage.local.get(['security_events'], (result) => {
      const events = result.security_events || [];
      events.unshift(event); //newest first

      //Keep last 1000 events
      if (events.length > 1000) {
        events.splice(1000);
      }

      chrome.storage.local.set({ security_events: events });
    });

    return event;
  }

  //Get severity for event type
  getEventSeverity(eventType) {
    const severityMap = {
      prompt_injection: 'high',
      secret_detected: 'critical',
      xss_detected: 'high',
      invalid_ioc: 'medium',
      api_error: 'medium',
      rate_limit: 'low',
      config_change: 'medium'
    };

    return severityMap[eventType] || 'info';
  }
}

//Export singleton
const securityValidator = new SecurityValidator();

//For use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SecurityValidator, securityValidator };
}

//Make globally available
if (typeof self !== 'undefined') {
  self.SecurityValidator = SecurityValidator;
  self.securityValidator = securityValidator;
}

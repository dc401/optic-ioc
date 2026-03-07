//Optic IOC - HTML Sanitizer
//Prevents XSS from LLM prompt injection attacks
//Sanitizes all user-controlled and LLM-generated content before rendering

class HTMLSanitizer {
  constructor() {
    //Allowed HTML tags for safe formatting
    this.allowedTags = new Set(['b', 'i', 'strong', 'em', 'br', 'ul', 'li', 'p']);

    //Dangerous characters that need escaping
    this.escapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;'
    };
  }

  //Escape HTML special characters to prevent XSS
  //Use this for text content that should be displayed as-is
  escapeHTML(text) {
    if (!text) return '';
    return String(text).replace(/[&<>"'/]/g, (char) => this.escapeMap[char]);
  }

  //Sanitize HTML by allowing only safe tags and removing all attributes
  //Use this when you need basic formatting but want to prevent script injection
  sanitizeHTML(html) {
    if (!html) return '';

    //Create temporary DOM element
    const temp = document.createElement('div');
    temp.textContent = html; //this escapes everything first

    //Parse as text and allow only whitelisted tags
    let sanitized = temp.innerHTML;

    //Remove all HTML tags except whitelisted ones (basic implementation)
    //For production, consider using DOMPurify library
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    sanitized = sanitized.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    sanitized = sanitized.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '');
    sanitized = sanitized.replace(/<embed[^>]*>/gi, '');
    sanitized = sanitized.replace(/on\w+\s*=\s*["'][^"']*["']/gi, ''); //remove event handlers
    sanitized = sanitized.replace(/on\w+\s*=\s*[^\s>]*/gi, ''); //remove event handlers without quotes
    sanitized = sanitized.replace(/javascript:/gi, ''); //remove javascript: URLs

    return sanitized;
  }

  //Create safe DOM elements from text (preferred method)
  //Returns DocumentFragment with safely created elements
  createSafeElements(structure) {
    const fragment = document.createDocumentFragment();

    for (const item of structure) {
      if (item.type === 'text') {
        //Text nodes are always safe
        fragment.appendChild(document.createTextNode(item.content));
      } else if (item.type === 'element') {
        //Create element and set text content (never innerHTML)
        const el = document.createElement(item.tag || 'div');
        if (item.text) {
          el.textContent = item.text; //safe - no HTML parsing
        }
        if (item.className) {
          el.className = item.className;
        }
        if (item.children) {
          el.appendChild(this.createSafeElements(item.children));
        }
        fragment.appendChild(el);
      }
    }

    return fragment;
  }

  //Validate and sanitize URL to prevent javascript: and data: URIs
  sanitizeURL(url) {
    if (!url) return '#';

    const trimmed = url.trim().toLowerCase();

    //Block dangerous protocols
    if (trimmed.startsWith('javascript:') ||
        trimmed.startsWith('data:') ||
        trimmed.startsWith('vbscript:') ||
        trimmed.startsWith('file:')) {
      console.warn('Blocked dangerous URL:', url);
      return '#';
    }

    //Only allow http(s) and relative URLs
    if (trimmed.startsWith('http://') ||
        trimmed.startsWith('https://') ||
        trimmed.startsWith('/') ||
        trimmed.startsWith('#')) {
      return url;
    }

    //Default to blocking unknown schemes
    console.warn('Blocked unknown URL scheme:', url);
    return '#';
  }

  //Sanitize LLM response before displaying
  //Extracts safe text and prevents code execution
  sanitizeLLMResponse(response) {
    if (!response) return { safe: true, sanitized: '' };

    const text = String(response);

    //Check for obvious injection attempts
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i, //event handlers
      /<iframe/i,
      /<object/i,
      /<embed/i,
      /eval\(/i,
      /document\.cookie/i,
      /localStorage/i,
      /sessionStorage/i
    ];

    let hasSuspiciousContent = false;
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(text)) {
        console.warn('LLM response contains suspicious content:', pattern);
        hasSuspiciousContent = true;
      }
    }

    //Escape all HTML
    const sanitized = this.escapeHTML(text);

    return {
      safe: !hasSuspiciousContent,
      sanitized: sanitized,
      original: text,
      warning: hasSuspiciousContent ? 'Response contains potentially malicious content' : null
    };
  }
}

//Export singleton
const htmlSanitizer = new HTMLSanitizer();

//For use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { HTMLSanitizer, htmlSanitizer };
}

//Make globally available
if (typeof self !== 'undefined') {
  self.HTMLSanitizer = HTMLSanitizer;
  self.htmlSanitizer = htmlSanitizer;
}

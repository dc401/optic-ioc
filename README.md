# Optic IOC - Threat Intelligence Extension

Browser extension for automatic IOC (Indicator of Compromise) detection and enrichment using AI and threat intelligence APIs.

## Quick Start

### 1. Get Your API Keys

You'll need at least **one** of these (both recommended):

- **Google Gemini API Key** (Required for AI analysis)
  - Get it from: https://aistudio.google.com/app/apikey
  - Free tier available

- **VirusTotal/GTI API Key** (Recommended for threat data)
  - Get it from: https://www.virustotal.com (sign up, go to API Key section)
  - Free tier: 4 requests/minute

### 2. Install Extension in Chrome

1. Navigate to `chrome://extensions` in Chrome
2. Enable **Developer Mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `optic-ioc` folder
5. Extension icon should appear in toolbar

### 3. Configure API Keys

1. Click the Optic IOC extension icon in toolbar
2. Go to **Settings** tab
3. Enter your Gemini API key
4. Enter your GTI API key (optional but recommended)
5. Set **Target Organization** (optional - e.g., "UKG" or "ukg.com")
6. Click **Save Settings**

### 4. Test Connection

1. Go to **Sources** tab
2. Click **Test Gemini Connection** (should show green checkmark)
3. Click **Test GTI Connection** (if you added key)

### 5. Try It Out!

#### Option A: Use Test Files (Recommended First)
Open the test HTML files in your browser:
- `test/optic-ioc-test-v1.html` - Basic IOC examples
- `test/optic-ioc-test-v2.html` - Advanced scenarios

#### Option B: Visit Real Threat Intelligence Sites
Navigate to any of these sites and enable IOC detection:

1. **ISC SANS Internet Storm Center**
   - https://isc.sans.edu
   - Daily threat intel reports with IOCs

2. **DFIR Report**
   - https://thedfirreport.com
   - Detailed incident reports with IOCs

3. **ThreatView**
   - https://threatview.io
   - Aggregated threat intelligence

### 6. Enable Detection on Current Site

1. Visit a page (test file or threat intel site)
2. Click the extension icon
3. Toggle **"Enable on this domain"** to ON
4. The page will automatically detect and highlight IOCs

## What It Does

### Automatic IOC Detection
Detects and highlights these indicators:
- **IP Addresses** (IPv4, IPv6)
- **Domains** (example.com, sub.domain.com)
- **URLs** (http://malicious.site/path)
- **File Hashes** (MD5, SHA1, SHA256)
- **CVEs** (CVE-2024-1234)
- **Emails** (attacker@evil.com)

### Automatic Defanging
Recognizes defanged IOCs and processes them:
- `hxxp://` → `http://`
- `example[.]com` → `example.com`
- `192[.]168[.]1[.]1` → `192.168.1.1`

### Color-Coded Threat Levels
After enrichment, IOCs are colored by severity:
- 🔴 **Red** = Critical (80-100 threat score)
- 🟠 **Orange** = High (60-79)
- 🟡 **Yellow** = Medium (40-59)
- 🔵 **Blue** = Low (20-39)
- 🟢 **Green** = Clean (0-19)

### AI-Powered Analysis
When IOCs are found, Gemini AI:
- Summarizes the overall threat landscape
- Identifies threat actor TTPs
- Assesses relevance to your organization
- Provides recommended actions
- **Security Alert**: Detects prompt injection, XSS, and secrets in page content

### Research Links
Right-click any highlighted IOC to pivot to:
- VirusTotal
- URLScan.io
- Shodan
- AlienVault OTX
- And more...

## How It Works

### Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Browser Page                        │
│  ┌────────────────────────────────────────────────┐  │
│  │ Content Script                                  │  │
│  │  - Scans page for IOCs                         │  │
│  │  - Highlights detected indicators              │  │
│  │  - Shows tooltips on hover                     │  │
│  │  - Displays AI analysis panel                  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
                         ↕️
┌──────────────────────────────────────────────────────┐
│             Service Worker (Background)               │
│  ┌────────────────────────────────────────────────┐  │
│  │ API Orchestrator                                │  │
│  │  1. GTI API → Get threat intelligence          │  │
│  │  2. Gemini API → Analyze with AI               │  │
│  │  - Rate limiting (respects API quotas)        │  │
│  │  - 30-day cache (faster repeat lookups)       │  │
│  │  - Security validation (prevents attacks)     │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
                         ↕️
        ┌────────────────────────────────┐
        │     External APIs               │
        │  • Google Gemini                │
        │  • VirusTotal (GTI)             │
        └────────────────────────────────┘
```

### Performance Features
- **Smart Caching**: IOCs cached for 30 days (instant on repeat visits)
- **Rate Limiting**: Respects API quotas (GTI: 4/min, Gemini: 60/min)
- **Private IP Filtering**: Skips RFC1918 addresses (10.x, 192.168.x, etc.)
- **Duplicate Prevention**: Each IOC enriched once per page

## Project Structure

```
optic-ioc/
├── src/
│   ├── lib/                    # Core utilities
│   │   ├── constants.js        # Configuration constants
│   │   ├── ioc-patterns.js     # IOC detection patterns
│   │   ├── sanitizer.js        # HTML/URL sanitization
│   │   ├── security-validator.js  # Attack detection
│   │   └── ui-helpers.js       # Panel/UI builders
│   │
│   ├── background/             # Service worker (background tasks)
│   │   ├── service-worker.js   # Main orchestrator
│   │   ├── gemini-client.js    # Gemini API integration
│   │   ├── gti-client.js       # VirusTotal API
│   │   ├── api-orchestrator.js # Coordinates API calls
│   │   ├── cache-manager.js    # 30-day LRU cache
│   │   └── rate-limiter.js     # Token bucket limiting
│   │
│   ├── content/                # Runs on web pages
│   │   └── content-script.js   # IOC detection & UI
│   │
│   └── popup/                  # Extension popup
│       ├── popup.html          # Settings UI
│       ├── popup.js            # Popup logic
│       └── popup.css           # Dark theme
│
├── test/                       # Test files
│   ├── optic-ioc-test-v1.html  # Basic IOC examples
│   └── optic-ioc-test-v2.html  # Advanced scenarios
│
└── manifest.json               # Chrome extension config
```

## Features

### Implemented ✅
- ✅ Automatic IOC detection (8 types)
- ✅ GTI threat intelligence enrichment
- ✅ Gemini AI analysis
- ✅ Color-coded severity highlighting
- ✅ Hover tooltips with enrichment data
- ✅ Right-click pivot links
- ✅ Aggregate threat summary panel
- ✅ Security attack detection (XSS, prompt injection, secrets)
- ✅ 30-day caching
- ✅ Rate limiting
- ✅ Encrypted API key storage

### Security Features 🔒
- **Encrypted Storage**: API keys encrypted with AES-256-GCM
- **Attack Detection**: Warns about XSS, prompt injection, leaked secrets
- **Input Validation**: All IOCs validated before processing
- **Private IP Filtering**: Skips internal addresses
- **URL Sanitization**: All external links sanitized
- **CSP Enforced**: Strict Content Security Policy

## Troubleshooting

### No IOCs Detected?
1. Make sure domain is **enabled** (click extension icon → toggle on)
2. Check page has actual IOCs (try test files first)
3. Open Developer Tools (F12) → Console → Look for "Optic IOC:" logs

### API Errors?
1. Verify API keys in **Settings** tab
2. Test connections in **Sources** tab
3. Check rate limits (GTI: 4 requests/minute)
4. Open Service Worker console:
   - Go to `chrome://extensions`
   - Find "Optic IOC"
   - Click "service worker" (blue link)
   - Check console for errors

### Nothing Happens on Page?
1. Hard refresh: `Ctrl+Shift+R` (Windows) or `Cmd+Shift+R` (Mac)
2. Check if content script loaded:
   - F12 → Console → Should see "Optic IOC content script loaded"
3. Disable/re-enable extension

## Privacy & Data

### What Gets Sent to APIs?
- **To Gemini**: IOC values, page content (for analysis)
- **To VirusTotal**: IOC values only

### What's Stored Locally?
- API keys (encrypted)
- Settings (unencrypted - no sensitive data)
- Cached enrichments (30-day expiry)
- Enabled domains list

### What's NOT Collected?
- No telemetry
- No usage tracking
- No data sent to third parties (only configured APIs)

## Important Disclaimers

⚠️ **AI-Generated Content**: Gemini summaries should be validated by human analysts. AI may misinterpret context or generate inaccurate assessments.

⚠️ **Educational Use**: This extension is for educational and research purposes. Always comply with your organization's security policies.

⚠️ **API Limits**: Free tier API keys have rate limits. Exceeding limits may result in temporary blocks.

## Resources

**Test Sites for IOC Detection**:
- ISC SANS: https://isc.sans.edu
- DFIR Report: https://thedfirreport.com
- ThreatView: https://threatview.io

**Get API Keys**:
- Gemini: https://aistudio.google.com/app/apikey
- VirusTotal: https://www.virustotal.com

**Documentation**:
- `/tmp/VALIDATION-COMPLETE.md` - Latest validation report
- `/tmp/simplify-refactoring-complete.md` - Code refactoring details

## Technical Details

### Rate Limits (Defaults)
- **GTI**: 4 requests/minute (free tier)
- **Gemini**: 60 requests/minute (free tier)

### Cache Settings
- **TTL**: 30 days
- **Max Size**: 50 MB
- **Storage**: Chrome local storage (encrypted)

### Supported IOC Types
| Type | Example | Pattern |
|------|---------|---------|
| IPv4 | `192.0.2.1` | `/\b(?:(?:25[0-5]...)\b/g` |
| IPv6 | `2001:db8::1` | `/(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/g` |
| Domain | `example.com` | `/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/g` |
| URL | `https://example.com/path` | `/https?:\/\/[^\s]+/g` |
| MD5 | `5d41402abc4b2a76b9719d911017c592` | `/\b[a-fA-F0-9]{32}\b/g` |
| SHA1 | `aaf4c61...` | `/\b[a-fA-F0-9]{40}\b/g` |
| SHA256 | `2c26b46...` | `/\b[a-fA-F0-9]{64}\b/g` |
| CVE | `CVE-2024-1234` | `/CVE-\d{4}-\d{4,7}/gi` |

---

**For Students**: Start with the test HTML files, get comfortable with the UI, then try it on real threat intel sites. Questions? Check the console logs (F12) for debugging info.

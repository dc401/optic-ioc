//Optic IOC - Content Script (Main Entry Point)
//Injected into every page to detect and highlight IOCs

//State
let config = null;
let isEnabled = false; //default OFF
let detectedIOCs = [];
let enrichmentCache = new Map(); //store enrichment results
let enrichedCount = 0;
let cachedCount = 0;
let enrichmentAbortController = null; //abort in-flight enrichment when domain disabled
let securityAlertTimer = null; //auto-dismiss timer

//SECURITY: Show security alert for detected attacks
//REFACTORED: Uses UIPanelBuilder to reduce duplication
function showSecurityAlert(data) {
  //Clear existing auto-dismiss timer
  if (securityAlertTimer) {
    clearTimeout(securityAlertTimer);
    securityAlertTimer = null;
  }

  const warnings = data.warnings || [];
  const stats = data.stats || {};

  //Reuse or create panel
  let alert = document.getElementById('optic-security-alert');
  if (!alert) {
    alert = document.createElement('div');
    alert.id = 'optic-security-alert';
    alert.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      width: 500px;
      max-width: 90vw;
      background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
      color: white;
      padding: 16px 20px;
      border-radius: 8px;
      z-index: ${OPTIC_CONSTANTS.Z_INDEX.SECURITY_ALERT};
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      font-weight: 600;
      box-shadow: 0 8px 24px rgba(255,0,0,0.4);
      border: 2px solid rgba(255,255,255,0.3);
    `;
    document.body.appendChild(alert);
  }

  //Reset state
  alert.style.opacity = '1';
  alert.style.transition = 'none';
  alert.innerHTML = ''; //Clear previous content

  //Header with icon, title, and close button
  const header = document.createElement('div');
  header.style.cssText = 'display: flex; align-items: center; gap: 12px; margin-bottom: 8px;';

  const icon = document.createElement('span');
  icon.textContent = '⚠️';
  icon.style.cssText = 'font-size: 24px;';

  const title = document.createElement('div');
  title.style.cssText = 'flex: 1;';
  title.textContent = '🔒 Security Alert: Potential Attack Detected';

  header.appendChild(icon);
  header.appendChild(title);
  header.appendChild(UIPanelBuilder.createCloseButton(() => {
    if (securityAlertTimer) clearTimeout(securityAlertTimer);
    alert.remove();
  }));
  alert.appendChild(header);

  //Warning details
  const details = document.createElement('div');
  details.style.cssText = 'font-size: 13px; font-weight: 400; margin-bottom: 12px; line-height: 1.5;';

  if (stats.injection_confidence > 0) {
    const line = document.createElement('div');
    line.textContent = `• Prompt injection detected (${stats.injection_confidence}% confidence)`;
    details.appendChild(line);
  }

  if (stats.xss_patterns > 0) {
    const line = document.createElement('div');
    line.textContent = `• ${stats.xss_patterns} XSS payload(s) detected`;
    details.appendChild(line);
  }

  if (stats.secrets_redacted > 0) {
    const line = document.createElement('div');
    line.textContent = `• ${stats.secrets_redacted} secret(s) redacted before analysis`;
    details.appendChild(line);
  }

  if (warnings.length > 0 && warnings.length <= 3) {
    warnings.forEach(w => {
      const line = document.createElement('div');
      line.textContent = `• ${w}`;
      details.appendChild(line);
    });
  }

  alert.appendChild(details);

  //Action message
  const action = document.createElement('div');
  action.style.cssText = 'font-size: 12px; opacity: 0.9; font-style: italic; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.3);';
  action.textContent = '⚡ Content was sanitized before analysis. Review this page carefully.';
  alert.appendChild(action);

  //Auto-dismiss after 15 seconds
  securityAlertTimer = UIPanelBuilder.autoDismiss(alert, 15000, true, () => {
    securityAlertTimer = null;
  });
}

//Initialize (only runs if domain is enabled)
async function init() {
  try {
    //Get current domain (main domain, not subdomain)
    const hostname = window.location.hostname;
    const parts = hostname.split('.');
    const currentDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

    //Check if domain is enabled
    const result = await chrome.storage.local.get(['enabled_domains']);
    const enabledDomains = result.enabled_domains || [];

    if (!enabledDomains.includes(currentDomain)) {
      console.log(`Optic IOC: Domain ${currentDomain} is DISABLED - no enrichment will run`);
      console.log(`Optic IOC: Enable this domain in the popup to activate IOC detection`);
      isEnabled = false;
      return;
    }

    console.log(`Optic IOC: Domain ${currentDomain} is ENABLED - starting IOC detection`);
    isEnabled = true;

    //Load config from background
    config = await sendMessage({ action: 'config.get' });

    //Extract IOCs from page
    await extractPageIOCs();

    if (detectedIOCs.length === 0) {
      //No hard IOCs found - send page to Gemini for AI analysis
      console.log('Optic IOC: No hard indicators found, analyzing page with Gemini...');
      await analyzePageWithAI();
    } else {
      //Enrich detected IOCs
      //FIXED: Await enrichment to complete before init returns
      await enrichIOCs();
      console.log(`Optic IOC: Found ${detectedIOCs.length} IOCs`);
    }

    //Setup context menu listener
    setupContextMenuListener();
  } catch (error) {
    console.error('Optic IOC initialization error:', error);
  }
}

//Extract IOCs from page text
async function extractPageIOCs() {
  try {
    //Get visible text from page
    const pageText = document.body.innerText;

    //Extract IOCs using service worker
    const result = await sendMessage({
      action: 'ioc.extract',
      data: { text: pageText }
    });

    detectedIOCs = result.iocs || [];

    //Simple highlighting (Phase 1 MVP - basic functionality)
    highlightIOCs();
  } catch (error) {
    console.error('Failed to extract IOCs:', error);
  }
}

//Analyze page with AI when no hard IOCs found
async function analyzePageWithAI() {
  try {
    const pageText = document.body.innerText;

    const analysis = await sendMessage({
      action: 'page.analyze',
      data: { pageText: pageText }
    });

    if (analysis && analysis.has_threats) {
      console.log(`Optic IOC: AI detected ${analysis.findings.length} potential threats (${analysis.threat_level})`);
      displayAIFindings(analysis);
    } else {
      console.log('Optic IOC: AI analysis complete - no threats detected');
    }
  } catch (error) {
    console.error('Failed to analyze page with AI:', error);
  }
}

//Display AI findings on page (SECURITY: uses safe DOM creation instead of innerHTML)
function displayAIFindings(analysis) {
  //Sanitize all LLM-generated content to prevent XSS
  const sanitizedAnalysis = {
    threat_level: htmlSanitizer.escapeHTML(analysis.threat_level || 'unknown'),
    summary: htmlSanitizer.escapeHTML(analysis.summary || 'No summary'),
    relevance_to_target: analysis.relevance_to_target ? htmlSanitizer.escapeHTML(analysis.relevance_to_target) : null,
    findings: (analysis.findings || []).map(f => ({
      type: htmlSanitizer.escapeHTML(f.type || 'unknown'),
      description: htmlSanitizer.escapeHTML(f.description || ''),
      evidence: htmlSanitizer.escapeHTML(f.evidence || ''),
      severity: htmlSanitizer.escapeHTML(f.severity || 'unknown')
    }))
  };

  //REFACTORED: Create panel using UIPanelBuilder
  const colors = UIPanelBuilder.getThreatColors(analysis.threat_level);
  const panel = UIPanelBuilder.createPanel({
    id: 'optic-ai-findings',
    position: 'right',
    offset: '20px',
    top: '80px',
    width: '360px',
    maxHeight: '80vh',
    background: colors.bg,
    border: `2px solid ${colors.border}`,
    zIndex: OPTIC_CONSTANTS.Z_INDEX.FINDINGS,
    extraStyles: ['padding: 0', 'overflow-y: auto']
  });

  //Header with close button
  const header = UIPanelBuilder.createHeader('🔍 AI Page Analysis', null, () => panel.remove());
  panel.appendChild(header);

  //Content container
  const content = document.createElement('div');
  content.style.cssText = 'padding: 16px;';
  panel.appendChild(content);

  //Threat info box
  const infoBox = document.createElement('div');
  infoBox.style.cssText = 'background: rgba(255,255,255,0.1); padding: 8px; border-radius: 4px; margin-bottom: 12px;';

  const threatLevelLabel = document.createElement('strong');
  threatLevelLabel.textContent = 'Threat Level: ';
  const threatLevelValue = document.createTextNode(sanitizedAnalysis.threat_level.toUpperCase());

  const br1 = document.createElement('br');

  const findingsLabel = document.createElement('strong');
  findingsLabel.textContent = 'Findings: ';
  const findingsValue = document.createTextNode(String(sanitizedAnalysis.findings.length));

  infoBox.appendChild(threatLevelLabel);
  infoBox.appendChild(threatLevelValue);
  infoBox.appendChild(br1);
  infoBox.appendChild(findingsLabel);
  infoBox.appendChild(findingsValue);
  content.appendChild(infoBox);

  //Summary
  const summaryPara = document.createElement('p');
  summaryPara.style.cssText = 'margin: 12px 0;';
  const summaryLabel = document.createElement('strong');
  summaryLabel.textContent = 'Summary:';
  const summaryBr = document.createElement('br');
  const summaryText = document.createTextNode(sanitizedAnalysis.summary);

  summaryPara.appendChild(summaryLabel);
  summaryPara.appendChild(summaryBr);
  summaryPara.appendChild(summaryText);
  content.appendChild(summaryPara);

  //Relevance (if available)
  if (sanitizedAnalysis.relevance_to_target) {
    const relevancePara = document.createElement('p');
    relevancePara.style.cssText = 'margin: 12px 0;';
    const relevanceLabel = document.createElement('strong');
    relevanceLabel.textContent = 'Relevance:';
    const relevanceBr = document.createElement('br');
    const relevanceText = document.createTextNode(sanitizedAnalysis.relevance_to_target);

    relevancePara.appendChild(relevanceLabel);
    relevancePara.appendChild(relevanceBr);
    relevancePara.appendChild(relevanceText);
    content.appendChild(relevancePara);
  }

  //Detailed findings
  if (sanitizedAnalysis.findings.length > 0) {
    const findingsDiv = document.createElement('div');
    findingsDiv.style.cssText = 'margin-top: 12px;';

    const findingsTitle = document.createElement('strong');
    findingsTitle.textContent = 'Detailed Findings:';
    findingsDiv.appendChild(findingsTitle);

    const findingsList = document.createElement('ul');
    findingsList.style.cssText = 'margin: 8px 0 0 20px; padding: 0;';

    for (const finding of sanitizedAnalysis.findings) {
      const li = document.createElement('li');
      li.style.cssText = 'margin: 8px 0;';

      const typeLabel = document.createElement('strong');
      typeLabel.textContent = finding.type + ':';
      li.appendChild(typeLabel);

      li.appendChild(document.createTextNode(' ' + finding.description));
      li.appendChild(document.createElement('br'));

      const evidenceSpan = document.createElement('span');
      evidenceSpan.style.cssText = 'color: #aaa; font-size: 11px;';
      evidenceSpan.textContent = finding.evidence;
      li.appendChild(evidenceSpan);
      li.appendChild(document.createElement('br'));

      const severitySpan = document.createElement('span');
      const severityColors = UIPanelBuilder.getThreatColors(finding.severity);
      severitySpan.style.cssText = `color: ${severityColors.text};`;
      severitySpan.textContent = 'Severity: ' + finding.severity;
      li.appendChild(severitySpan);

      findingsList.appendChild(li);
    }

    findingsDiv.appendChild(findingsList);
    content.appendChild(findingsDiv);
  }

  //Research links (safe URLs only)
  const linksDiv = document.createElement('div');
  linksDiv.style.cssText = 'margin-top: 16px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.2);';

  const linksTitle = document.createElement('strong');
  linksTitle.textContent = 'Research Links:';
  linksDiv.appendChild(linksTitle);

  const linksContainer = document.createElement('div');
  linksContainer.style.cssText = 'margin-top: 8px;';

  //Google search link
  const googleLink = document.createElement('a');
  const googleUrl = 'https://www.google.com/search?q=' + encodeURIComponent('threat intelligence ' + (analysis.summary || ''));
  googleLink.href = htmlSanitizer.sanitizeURL(googleUrl);
  googleLink.target = '_blank';
  googleLink.rel = 'noopener noreferrer'; //security: prevent window.opener access
  googleLink.style.cssText = 'display: block; color: #4a9eff; margin: 4px 0;';
  googleLink.textContent = '🔍 Google Search';
  linksContainer.appendChild(googleLink);

  //GTI link
  const gtiLink = document.createElement('a');
  const gtiUrl = 'https://www.virustotal.com/gui/search/' + encodeURIComponent(document.location.hostname);
  gtiLink.href = htmlSanitizer.sanitizeURL(gtiUrl);
  gtiLink.target = '_blank';
  gtiLink.rel = 'noopener noreferrer';
  gtiLink.style.cssText = 'display: block; color: #4a9eff; margin: 4px 0;';
  gtiLink.textContent = '🛡️ Check Site in GTI';
  linksContainer.appendChild(gtiLink);

  //URLScan link
  const urlscanLink = document.createElement('a');
  const urlscanUrl = 'https://urlscan.io/search/#' + encodeURIComponent(document.location.hostname);
  urlscanLink.href = htmlSanitizer.sanitizeURL(urlscanUrl);
  urlscanLink.target = '_blank';
  urlscanLink.rel = 'noopener noreferrer';
  urlscanLink.style.cssText = 'display: block; color: #4a9eff; margin: 4px 0;';
  urlscanLink.textContent = '🌐 URLScan.io';
  linksContainer.appendChild(urlscanLink);

  linksDiv.appendChild(linksContainer);
  content.appendChild(linksDiv);

  document.body.appendChild(panel);

  //Auto-dismiss after 30 seconds (using UIPanelBuilder)
  UIPanelBuilder.autoDismiss(panel, 30000, true);
}

//Display aggregate IOC summary panel (TOP-RIGHT, always show if IOCs found)
async function displayAggregateSummary() {
  try {
    console.log(`[AGGREGATE] ========== FUNCTION CALLED ==========`);
    console.log(`[AGGREGATE] enrichedCount: ${enrichedCount}, cachedCount: ${cachedCount}, detectedIOCs: ${detectedIOCs.length}`);

    if (detectedIOCs.length === 0) {
      console.log(`[AGGREGATE] ✗ No IOCs detected - skipping`);
      return;
    }

    const totalEnriched = enrichedCount + cachedCount;
    console.log(`[AGGREGATE] ✓ ${detectedIOCs.length} IOCs found - will generate aggregate analysis`);

    //Gather all enriched IOC data
    const iocSummaries = [];
    for (const ioc of detectedIOCs) {
      const enrichment = enrichmentCache.get(ioc.value);
      if (enrichment && !enrichment.error) {
        iocSummaries.push({
          type: ioc.type,
          value: ioc.value,
          severity: enrichment.severity || 'unknown',
          verdict: enrichment.verdict || 'unknown',
          details: enrichment.details || {}
        });
      }
    }

    console.log(`[AGGREGATE] Collected ${iocSummaries.length} IOC summaries for Gemini`);

    //Request aggregate analysis from Gemini
    console.log(`[AGGREGATE] Calling Gemini API for aggregate analysis...`);
    const aggregateAnalysis = await sendMessage({
      action: 'ioc.aggregateSummary',
      data: {
        iocs: iocSummaries,
        pageUrl: window.location.href,
        enrichedCount: totalEnriched,
        totalCount: detectedIOCs.length
      }
    });

    console.log(`[AGGREGATE] Gemini response received:`, aggregateAnalysis);

    if (!aggregateAnalysis || aggregateAnalysis.error) {
      console.error('[AGGREGATE] ✗ Failed to generate summary:', aggregateAnalysis?.error);
      return;
    }

    //Sanitize LLM output
    const sanitized = {
      risk_level: htmlSanitizer.escapeHTML(aggregateAnalysis.risk_level || 'medium'),
      analysis: htmlSanitizer.escapeHTML(aggregateAnalysis.analysis || 'No analysis available')
    };

    //Remove existing panel if present
    const existingPanel = document.getElementById('optic-summary-panel');
    if (existingPanel) existingPanel.remove();

    //REFACTORED: Create aggregate summary panel using UIPanelBuilder
    const panel = UIPanelBuilder.createPanel({
      id: 'optic-summary-panel',
      position: 'right',
      offset: '20px',
      top: '80px',
      width: '420px',
      maxHeight: '85vh',
      zIndex: OPTIC_CONSTANTS.Z_INDEX.SUMMARY,
      extraStyles: ['padding: 0']
    });

    console.log(`[AGGREGATE] Panel element created with ID: ${panel.id}`);

    //Header with expand/collapse
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      background: rgba(74, 158, 255, 0.15);
      border-bottom: 1px solid rgba(74, 158, 255, 0.3);
      cursor: pointer;
    `;

    const headerText = document.createElement('div');
    headerText.style.cssText = 'flex: 1;';

    const title = document.createElement('h3');
    title.style.cssText = 'margin: 0; font-size: 15px; font-weight: 600;';
    title.textContent = `📊 Threat Analysis (${detectedIOCs.length} IOCs)`;

    const subtitle = document.createElement('div');
    subtitle.style.cssText = 'font-size: 11px; color: #aaa; margin-top: 2px;';
    subtitle.textContent = `Risk: ${sanitized.risk_level.toUpperCase()} | ${totalEnriched} Enriched`;

    headerText.appendChild(title);
    headerText.appendChild(subtitle);

    const controls = document.createElement('div');
    controls.style.cssText = 'display: flex; gap: 8px;';

    const toggleBtn = document.createElement('button');
    toggleBtn.style.cssText = 'background: none; border: none; color: white; font-size: 18px; cursor: pointer; padding: 0; width: 24px; height: 24px;';
    toggleBtn.textContent = '−';

    controls.appendChild(toggleBtn);
    controls.appendChild(UIPanelBuilder.createCloseButton(() => panel.remove()));

    header.appendChild(headerText);
    header.appendChild(controls);
    panel.appendChild(header);

    //Content (collapsible) - using UIPanelBuilder helper
    const content = UIPanelBuilder.createContent('calc(70vh - 60px)');

    //Display analysis text (SECURITY: using textContent prevents XSS)
    const analysisDiv = document.createElement('div');
    analysisDiv.style.cssText = 'white-space: pre-wrap; word-wrap: break-word;';
    analysisDiv.textContent = sanitized.analysis; //textContent auto-escapes HTML
    content.appendChild(analysisDiv);

    panel.appendChild(content);

    //Toggle expand/collapse
    let isCollapsed = false;
    header.onclick = () => {
      isCollapsed = !isCollapsed;
      content.style.display = isCollapsed ? 'none' : 'block';
      toggleBtn.textContent = isCollapsed ? '+' : '−';
    };

    console.log(`[AGGREGATE] ✓ Panel created - appending to document.body...`);
    console.log(`[AGGREGATE] document.body exists: ${!!document.body}`);

    if (!document.body) {
      console.error(`[AGGREGATE] ✗✗ CRITICAL: document.body is NULL - cannot append panel!`);
      return;
    }

    document.body.appendChild(panel);
    console.log(`[AGGREGATE] ✓✓✓ Panel successfully appended to DOM!`);
    console.log(`[AGGREGATE] Panel position: TOP-RIGHT (top=80px, right=20px, z-index=9999999)`);
    console.log(`[AGGREGATE] Panel width: 420px, max-height: 85vh`);
    console.log(`[AGGREGATE] Panel visible: ${panel.offsetHeight > 0}, offsetHeight: ${panel.offsetHeight}px`);
    console.log(`[AGGREGATE] Panel in DOM: ${document.getElementById('optic-summary-panel') !== null}`);
  } catch (error) {
    console.error('[AGGREGATE] ✗✗ ERROR displaying aggregate summary:', error);
    console.error('[AGGREGATE] Stack trace:', error.stack);
  }
}

//Enrich detected IOCs (PERFORMANCE: Parallel enrichment)
async function enrichIOCs() {
  if (detectedIOCs.length === 0) return;

  //Reset counters
  enrichedCount = 0;
  cachedCount = 0;

  //Create AbortController for this enrichment session
  enrichmentAbortController = new AbortController();
  const signal = enrichmentAbortController.signal;

  //Process ALL IOCs (removed 20 limit for analysts who need full coverage)
  const toEnrich = detectedIOCs;
  console.log(`Optic IOC: Enriching ${toEnrich.length} indicators IN PARALLEL...`);

  //Add loading class to all highlights
  document.querySelectorAll('.optic-highlight').forEach(el => el.classList.add('loading'));

  //Create progress indicator
  createProgressIndicator(toEnrich.length);

  try {
    //PARALLEL ENRICHMENT: Process all IOCs at once (much faster)
    const enrichmentPromises = toEnrich.map(async (ioc, index) => {
      try {
        //Check if aborted
        if (signal.aborted) {
          console.log(`✗ [${index + 1}/${toEnrich.length}] Aborted: ${ioc.value}`);
          return { success: false, ioc, aborted: true };
        }

        //Check cache first (sync operation)
        let enrichment = enrichmentCache.get(ioc.value);
        let fromCache = false;

        if (!enrichment) {
          //Check abort again before API call
          if (signal.aborted) {
            return { success: false, ioc, aborted: true };
          }

          //API call (async - runs in parallel)
          enrichment = await sendMessage({
            action: 'ioc.enrich',
            data: {
              ioc_type: ioc.type,
              ioc_value: ioc.value
            }
          });
          enrichedCount++;
          console.log(`✓ [${index + 1}/${toEnrich.length}] Enriched ${ioc.value}: ${enrichment?.severity || 'unknown'}`);
        } else {
          fromCache = true;
          cachedCount++;
          console.log(`✓ [${index + 1}/${toEnrich.length}] From cache: ${ioc.value}`);
        }

        //Update progress (if not aborted)
        if (!signal.aborted) {
          updateProgressIndicator(index + 1, toEnrich.length, ioc.value);
        }

        if (enrichment && !enrichment.error) {
          enrichmentCache.set(ioc.value, enrichment);
          //Update highlight with severity and remove loading
          updateHighlight(ioc.value, enrichment);
          return { success: true, ioc, enrichment };
        } else {
          console.error(`✗ Enrichment failed for ${ioc.value}:`, enrichment?.error);
          removeLoading(ioc.value);
          return { success: false, ioc, error: enrichment?.error };
        }
      } catch (error) {
        console.error(`✗ Failed to enrich ${ioc.value}:`, error);
        removeLoading(ioc.value);
        return { success: false, ioc, error: error.message };
      }
    });

    //Wait for all enrichments to complete (or abort)
    const results = await Promise.all(enrichmentPromises);

    //Remove progress indicator
    removeProgressIndicator();

    //Summary
    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success && !r.aborted).length;
    const aborted = results.filter(r => r.aborted).length;

    if (aborted > 0) {
      console.log(`Optic IOC: Enrichment ABORTED - ${aborted} requests cancelled`);
    }
    console.log(`Optic IOC: Enrichment complete - ${successful} successful, ${failed} failed`);
    console.log(`           ${enrichedCount} new API calls, ${cachedCount} from cache`);

    //Generate aggregate summary (ALWAYS show if IOCs detected, even if all cached)
    console.log(`[AGGREGATE] ==========================================`);
    console.log(`[AGGREGATE] Checking if aggregate summary should be displayed...`);
    console.log(`[AGGREGATE] detectedIOCs.length: ${detectedIOCs.length}`);
    console.log(`[AGGREGATE] aborted: ${aborted}, successful: ${successful}, cachedCount: ${cachedCount}`);

    if (aborted === 0 && detectedIOCs.length > 0) {
      console.log(`[AGGREGATE] ✓✓✓ CALLING displayAggregateSummary() NOW!`);
      displayAggregateSummary().catch(err => {
        console.error(`[AGGREGATE] Async error in displayAggregateSummary:`, err);
      });
    } else {
      console.log(`[AGGREGATE] ✗ Skipping - aborted=${aborted}, IOCs=${detectedIOCs.length}`);
    }
  } catch (error) {
    console.error('Optic IOC: Enrichment error:', error);
    removeProgressIndicator();
  } finally {
    //Cleanup AbortController
    enrichmentAbortController = null;
  }
}

//Remove loading indicator from IOC
function removeLoading(iocValue) {
  const highlights = document.querySelectorAll(`[data-ioc-value="${iocValue}"]`);
  highlights.forEach(el => el.classList.remove('loading'));
}

//Simple IOC highlighting (MVP version)
function highlightIOCs() {
  if (detectedIOCs.length === 0) return;

  //Highlight each IOC with its type information
  for (const ioc of detectedIOCs) {
    highlightText(ioc.value, ioc.type);
  }
}

//Update existing highlight with enrichment data
function updateHighlight(iocValue, enrichment) {
  if (!enrichment) {
    console.warn('No enrichment data for:', iocValue);
    return;
  }

  //Find all highlight spans for this IOC using data attribute
  const highlights = document.querySelectorAll(`[data-ioc-value="${iocValue}"]`);

  console.log(`Updating ${highlights.length} highlights for ${iocValue}`);

  if (highlights.length === 0) {
    //Fallback to text content match
    const allHighlights = document.querySelectorAll('.optic-highlight');
    for (const highlight of allHighlights) {
      if (highlight.textContent === iocValue) {
        applyEnrichment(highlight, enrichment);
      }
    }
  } else {
    highlights.forEach(highlight => applyEnrichment(highlight, enrichment));
  }
}

//Apply enrichment to highlight element
function applyEnrichment(highlight, enrichment) {
  //Remove loading state
  highlight.classList.remove('loading');

  //Add severity class
  const severity = enrichment.severity || 'unknown';
  highlight.classList.add(`severity-${severity}`);

  //Update tooltip with enrichment summary
  try {
    const tooltip = buildTooltip(enrichment);
    highlight.title = tooltip;
    console.log(`Set tooltip for ${enrichment.ioc_value}: ${tooltip.substring(0, 50)}...`);
  } catch (error) {
    console.error('Failed to build tooltip:', error);
    highlight.title = `IOC: ${enrichment.ioc_value}\nSeverity: ${severity}\nRight-click for pivots`;
  }

  //Add data attributes for tracking
  highlight.dataset.severity = severity;
  highlight.dataset.severityScore = enrichment.severity_score || 0;
}

//Build tooltip text from enrichment data
function buildTooltip(enrichment) {
  const lines = [];

  lines.push(`IOC: ${enrichment.ioc_value || 'Unknown'}`);

  const severity = enrichment.severity || 'unknown';
  const severityScore = enrichment.severity_score || 0;
  lines.push(`Severity: ${severity.toUpperCase()} (${severityScore}/100)`);

  if (enrichment.summary) {
    lines.push(`Summary: ${enrichment.summary}`);
  }

  if (enrichment.details?.gti_stats) {
    const stats = enrichment.details.gti_stats;
    lines.push(`GTI: ${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious`);
  }

  lines.push('\nRight-click for pivot links');

  return lines.join('\n');
}

//Highlight specific text in page
function highlightText(text, iocType) {
  //Simple text node walker
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        //Skip script, style, and already highlighted nodes
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE') {
          return NodeFilter.FILTER_REJECT;
        }
        if (parent.classList.contains('optic-highlight')) {
          return NodeFilter.FILTER_REJECT;
        }
        //Skip our own UI elements
        if (parent.closest('#optic-progress-indicator, #optic-ai-findings, #optic-summary-panel')) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );

  const nodesToHighlight = [];
  let currentNode;

  while (currentNode = walker.nextNode()) {
    if (currentNode.textContent.includes(text)) {
      nodesToHighlight.push(currentNode);
    }
  }

  //Highlight nodes
  for (const node of nodesToHighlight) {
    highlightNode(node, text, iocType);
  }
}

//Highlight text within node
function highlightNode(node, text, iocType) {
  const parent = node.parentElement;
  const content = node.textContent;
  const index = content.indexOf(text);

  if (index === -1) return;

  //Split text node
  const beforeText = content.substring(0, index);
  const matchText = content.substring(index, index + text.length);
  const afterText = content.substring(index + text.length);

  //Create highlight span
  const span = document.createElement('span');
  span.className = 'optic-highlight';
  span.textContent = matchText;
  span.title = 'IOC detected - enriching... (right-click for pivot links)';
  span.dataset.iocValue = matchText; //Store for easy lookup
  span.dataset.iocType = iocType; //CRITICAL: Store type for export submission

  //Replace node with highlighted version
  const fragment = document.createDocumentFragment();
  if (beforeText) fragment.appendChild(document.createTextNode(beforeText));
  fragment.appendChild(span);
  if (afterText) fragment.appendChild(document.createTextNode(afterText));

  parent.replaceChild(fragment, node);
}

//Create progress indicator (fixed top-right of screen)
function createProgressIndicator(total) {
  //Remove existing if any
  removeProgressIndicator();

  const indicator = document.createElement('div');
  indicator.id = 'optic-progress-indicator';
  indicator.style.cssText = `
    position: fixed;
    top: 10px;
    right: 10px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    z-index: ${OPTIC_CONSTANTS.Z_INDEX.PROGRESS};
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    font-weight: 600;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    min-width: 280px;
    backdrop-filter: blur(10px);
  `;

  indicator.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <div class="spinner" style="width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 0.8s linear infinite;"></div>
      <div style="flex: 1;">
        <div id="optic-progress-text">Enriching IOCs...</div>
        <div id="optic-progress-detail" style="font-size: 11px; opacity: 0.9; margin-top: 2px;">0 / ${total}</div>
      </div>
      <div id="optic-progress-percent" style="font-size: 18px; font-weight: 700;">0%</div>
    </div>
    <div style="width: 100%; height: 3px; background: rgba(255,255,255,0.2); border-radius: 2px; margin-top: 8px; overflow: hidden;">
      <div id="optic-progress-bar" style="height: 100%; background: white; width: 0%; transition: width 0.3s ease;"></div>
    </div>
  `;

  //Add animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  `;
  indicator.appendChild(style);

  document.body.appendChild(indicator);
}

//Update progress indicator
function updateProgressIndicator(current, total, currentIOC) {
  const indicator = document.getElementById('optic-progress-indicator');
  if (!indicator) return;

  const percent = Math.round((current / total) * 100);

  const textEl = document.getElementById('optic-progress-text');
  const detailEl = document.getElementById('optic-progress-detail');
  const percentEl = document.getElementById('optic-progress-percent');
  const barEl = document.getElementById('optic-progress-bar');

  if (textEl) textEl.textContent = `Enriching: ${currentIOC || 'IOCs'}...`;
  if (detailEl) detailEl.textContent = `${current} / ${total}`;
  if (percentEl) percentEl.textContent = `${percent}%`;
  if (barEl) barEl.style.width = `${percent}%`;
}

//Remove progress indicator
function removeProgressIndicator() {
  const indicator = document.getElementById('optic-progress-indicator');
  if (indicator) {
    indicator.style.transition = 'opacity 0.3s';
    indicator.style.opacity = '0';
    setTimeout(() => indicator.remove(), 300);
  }
}

//Show API health notification (persistent until user closes)
function showAPIHealthNotification(healthStatus) {
  //Remove existing notification if any
  removeAPIHealthNotification();

  const failures = [];
  if (healthStatus.gemini?.status === 'failed') {
    failures.push({
      api: 'Gemini',
      error: healthStatus.gemini.error || 'Connection failed'
    });
  }
  if (healthStatus.gti?.status === 'failed') {
    failures.push({
      api: 'GTI',
      error: healthStatus.gti.error || 'Connection failed'
    });
  }

  if (failures.length === 0) return;

  const notification = document.createElement('div');
  notification.id = 'optic-api-health-notification';
  notification.style.cssText = `
    position: fixed;
    top: 10px;
    right: 10px;
    background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
    color: white;
    padding: 14px 18px;
    border-radius: 8px;
    z-index: ${OPTIC_CONSTANTS.Z_INDEX.NOTIFICATION};
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    font-weight: 600;
    box-shadow: 0 4px 16px rgba(255,0,0,0.4);
    min-width: 320px;
    max-width: 400px;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.1);
  `;

  const failuresList = failures.map(f =>
    `<div style="margin-top: 6px; padding: 6px 8px; background: rgba(0,0,0,0.2); border-radius: 4px;">
      <div style="font-weight: 700; margin-bottom: 2px;">⚠️ ${f.api} API</div>
      <div style="font-size: 11px; opacity: 0.9; font-weight: 400;">${f.error}</div>
    </div>`
  ).join('');

  notification.innerHTML = `
    <div style="display: flex; align-items: start; gap: 10px;">
      <div style="flex: 1;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
          <div style="font-size: 15px; font-weight: 700;">🔴 API Health Check Failed</div>
        </div>
        <div style="font-size: 11px; opacity: 0.9; margin-bottom: 8px;">Last checked: ${new Date(healthStatus.timestamp).toLocaleTimeString()}</div>
        ${failuresList}
        <div style="font-size: 10px; opacity: 0.8; margin-top: 8px; font-style: italic;">
          Check Settings → Sources tab to reconfigure API keys
        </div>
      </div>
      <button id="optic-close-health-notification" style="
        background: rgba(255,255,255,0.2);
        border: none;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
        font-weight: 700;
        transition: all 0.2s;
        flex-shrink: 0;
      " onmouseover="this.style.background='rgba(255,255,255,0.3)'" onmouseout="this.style.background='rgba(255,255,255,0.2)'">✖</button>
    </div>
  `;

  document.body.appendChild(notification);

  //Add close button listener
  document.getElementById('optic-close-health-notification')?.addEventListener('click', () => {
    removeAPIHealthNotification();
  });
}

//Remove API health notification
function removeAPIHealthNotification() {
  const notification = document.getElementById('optic-api-health-notification');
  if (notification) {
    notification.style.opacity = '0';
    notification.style.transition = 'opacity 0.3s';
    setTimeout(() => notification.remove(), 300);
  }
}

//Setup context menu listener
function setupContextMenuListener() {
  document.addEventListener('selectionchange', () => {
    const selection = window.getSelection();
    const text = selection.toString().trim();

    if (text && text.length > 0 && text.length < 100) {
      //Update context menu in background
      sendMessage({
        action: 'context.update',
        data: { selection: text }
      });
    }
  });
}

//Send message to service worker
async function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (response?.error) {
        reject(new Error(response.error));
      } else {
        resolve(response);
      }
    });
  });
}

//Refresh analysis (clear and re-run)
async function refreshAnalysis(bypassCache = false, forceAIAnalysis = false) {
  console.log('Optic IOC: Refreshing analysis...');

  //Clear existing highlights
  document.querySelectorAll('.optic-highlight').forEach(highlight => {
    const parent = highlight.parentNode;
    const textNode = document.createTextNode(highlight.textContent);
    parent.replaceChild(textNode, highlight);
    //Merge adjacent text nodes
    parent.normalize();
  });

  //Clear AI findings panel
  const aiPanel = document.getElementById('optic-ai-findings');
  if (aiPanel) {
    aiPanel.remove();
  }

  //Clear state
  detectedIOCs = [];
  enrichedCount = 0;
  cachedCount = 0;

  if (bypassCache) {
    enrichmentCache.clear();
  }

  //Re-run extraction
  await extractPageIOCs();

  //Always enrich if IOCs found
  if (detectedIOCs.length > 0) {
    enrichIOCs();
    console.log(`Optic IOC: Found ${detectedIOCs.length} IOCs`);
  }

  //Run AI analysis if forced (manual scan) OR no IOCs found
  if (forceAIAnalysis || detectedIOCs.length === 0) {
    console.log('Optic IOC: Running AI page analysis...');
    await analyzePageWithAI();
  }

  console.log('Optic IOC: Refresh complete');
}

//Listen for messages from popup/background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'page.refresh') {
    //Manual scan - always run both regex and AI analysis
    refreshAnalysis(message.data?.bypassCache || false, true)
      .then(() => sendResponse({ success: true, iocs: detectedIOCs.length }))
      .catch(error => sendResponse({ error: error.message }));
    return true; //async response
  }

  if (message.action === 'page.getStats') {
    //Return current page stats
    sendResponse({
      total: detectedIOCs.length,
      enriched: enrichedCount,
      cached: cachedCount,
      enabled: isEnabled
    });
    return true;
  }

  if (message.action === 'api.healthAlert') {
    //API health check failed - show persistent notification
    showAPIHealthNotification(message.data);
    sendResponse({ success: true });
    return true;
  }

  if (message.action === 'domain.toggle') {
    //Domain was toggled - apply change
    if (message.data.enabled) {
      //Domain enabled - re-run init
      isEnabled = true;
      init().then(() => sendResponse({ success: true }));
    } else {
      //Domain disabled - ABORT IN-FLIGHT ENRICHMENT and clear state
      isEnabled = false;

      //CRITICAL: Abort any running enrichment (kills queued API calls)
      if (enrichmentAbortController) {
        console.log('Optic IOC: Aborting in-flight enrichment...');
        enrichmentAbortController.abort();
        enrichmentAbortController = null;
      }

      //Remove progress indicator
      removeProgressIndicator();

      //Clear highlights
      document.querySelectorAll('.optic-highlight').forEach(highlight => {
        const parent = highlight.parentNode;
        const textNode = document.createTextNode(highlight.textContent);
        parent.replaceChild(textNode, highlight);
        parent.normalize();
      });

      //Clear AI panel
      const aiPanel = document.getElementById('optic-ai-findings');
      if (aiPanel) aiPanel.remove();

      //Clear state
      detectedIOCs = [];
      enrichmentCache.clear();
      enrichedCount = 0;
      cachedCount = 0;
      sendResponse({ success: true });
    }
    return true; //async response
  }

  if (message.action === 'getClickedIOC') {
    //Context menu needs IOC type from clicked highlight element
    const selection = message.data.selection;
    const highlights = document.querySelectorAll('.optic-highlight');

    //Find highlight matching the selection text
    for (const highlight of highlights) {
      if (highlight.textContent === selection) {
        sendResponse({
          type: highlight.dataset.iocType,
          value: highlight.dataset.iocValue
        });
        return true;
      }
    }

    //Not found in highlights (fallback to extraction)
    sendResponse(null);
    return true;
  }

  if (message.action === 'security.attackDetected') {
    //SECURITY: Display attack notification to user
    showSecurityAlert(message.data);
    sendResponse({ success: true });
    return true;
  }
});

//Initialize when DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

console.log('Optic IOC content script loaded');

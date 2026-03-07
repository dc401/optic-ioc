//Optic IOC - Popup UI Logic

//State
let config = null;
let secrets = null;
let authStatus = null;
let currentDomain = null;
let siteWhitelist = [];

//Initialize on load
document.addEventListener('DOMContentLoaded', async () => {
  await init();
});

//Initialize popup
async function init() {
  //Setup tab navigation
  setupTabs();

  //Setup event listeners
  setupEventListeners();

  //Load config and secrets
  await loadConfig();

  //Load current site and whitelist
  await loadCurrentSite();

  //Load statistics
  await loadStats();

  //Render UI
  renderSettings();
  //renderSources(); //DISABLED - sources-list container removed from popup.html
  renderPivots();
  await renderDomains();
}

//Setup tab navigation
function setupTabs() {
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const tabName = tab.dataset.tab;

      //Update active tab
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      //Update active content
      tabContents.forEach(content => {
        if (content.id === `tab-${tabName}`) {
          content.classList.add('active');
        } else {
          content.classList.remove('active');
        }
      });
    });
  });
}

//Setup event listeners
function setupEventListeners() {
  //Helper to safely add event listener
  const addListener = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
    else console.warn(`[POPUP] Element not found: ${id}`);
  };

  //Settings
  addListener('save-settings', 'click', saveSettings);

  //Toggle mask buttons for API keys
  document.querySelectorAll('.btn-toggle-mask').forEach(btn => {
    btn.addEventListener('click', toggleMask);
  });

  //Domain toggle
  addListener('domain-enabled', 'change', toggleCurrentDomain);

  //Cache
  addListener('clear-cache', 'click', clearCache);
  addListener('refresh-page', 'click', refreshPage);

  //Config actions
  addListener('export-config', 'click', exportConfig);
  addListener('import-config', 'click', importConfig);
  addListener('reset-config', 'click', resetConfig);

  //API Testing
  addListener('test-gemini', 'click', testGeminiAPI);
  addListener('test-gti', 'click', testGTIAPI);

  //Pivot Configuration
  addListener('add-pivot-btn', 'click', showPivotForm);
  addListener('save-pivot', 'click', savePivot);
  addListener('cancel-pivot', 'click', hidePivotForm);

  //Domain Whitelist
  addListener('export-domains', 'click', exportDomains);
  addListener('import-domains', 'click', importDomains);
  addListener('clear-domains', 'click', clearDomains);

  //Service Worker Console
  addListener('open-service-worker', 'click', openServiceWorker);
}

//Toggle password mask for API key fields
function toggleMask(event) {
  const btn = event.currentTarget;
  const targetId = btn.dataset.target;
  const input = document.getElementById(targetId);

  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁';
  }
}

//Load config
async function loadConfig() {
  try {
    config = await sendMessage({ action: 'config.get' });
    secrets = await sendMessage({ action: 'secrets.get' });
  } catch (error) {
    console.error('Failed to load config:', error);
    config = {};
    secrets = {};
  }
}

//Load current domain and enabled status
async function loadCurrentSite() {
  try {
    //Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
      document.getElementById('current-domain').textContent = 'Unknown';
      document.getElementById('domain-status').textContent = 'No Tab';
      document.getElementById('domain-status').style.color = 'var(--text-muted)';
      return;
    }

    //Parse domain from URL
    try {
      const url = new URL(tab.url);
      currentDomain = url.hostname;

      //Extract main domain (e.g., example.com from sub.example.com)
      const parts = currentDomain.split('.');
      const mainDomain = parts.length >= 2 ? parts.slice(-2).join('.') : currentDomain;

      document.getElementById('current-domain').textContent = mainDomain;
      currentDomain = mainDomain; //use main domain for storage
    } catch (urlError) {
      console.error('Failed to parse URL:', urlError);
      document.getElementById('current-domain').textContent = 'Invalid URL';
      document.getElementById('domain-status').textContent = 'Invalid';
      return;
    }

    //Load enabled domains from storage
    const result = await chrome.storage.local.get(['enabled_domains']);
    siteWhitelist = result.enabled_domains || [];

    //Check if current domain is enabled
    const isEnabled = siteWhitelist.includes(currentDomain);
    document.getElementById('domain-enabled').checked = isEnabled;

    //Update status display
    if (isEnabled) {
      document.getElementById('domain-status').textContent = '✓ Enabled';
      document.getElementById('domain-status').style.color = 'var(--success)';
    } else {
      document.getElementById('domain-status').textContent = '✗ Disabled';
      document.getElementById('domain-status').style.color = 'var(--danger)';
    }

    //Load current page stats
    await loadPageStats(tab);
  } catch (error) {
    console.error('Failed to load current domain:', error);
    document.getElementById('current-domain').textContent = 'Error';
    document.getElementById('domain-status').textContent = 'Error';
  }
}

//Toggle current domain enable/disable
async function toggleCurrentDomain(event) {
  const enabled = event.target.checked;

  try {
    if (enabled) {
      //Add to enabled domains list
      if (!siteWhitelist.includes(currentDomain)) {
        siteWhitelist.push(currentDomain);

        //Enforce 10,000 domain limit (FIFO - remove oldest)
        if (siteWhitelist.length > 10000) {
          siteWhitelist = siteWhitelist.slice(-10000);
          showNotification('Removed oldest domains to stay under 10,000 limit', 'info');
        }
      }
    } else {
      //Remove from enabled domains list
      siteWhitelist = siteWhitelist.filter(domain => domain !== currentDomain);
    }

    //Save to storage (use consistent key)
    await chrome.storage.local.set({ enabled_domains: siteWhitelist });

    //Update status display
    if (enabled) {
      document.getElementById('domain-status').textContent = '✓ Enabled';
      document.getElementById('domain-status').style.color = 'var(--success)';
      showNotification(`Enabled IOC detection on ${currentDomain}`, 'success');
    } else {
      document.getElementById('domain-status').textContent = '✗ Disabled';
      document.getElementById('domain-status').style.color = 'var(--danger)';
      showNotification(`Disabled IOC detection on ${currentDomain}`, 'success');
    }

    //Notify content script to apply change
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, {
        action: 'domain.toggle',
        data: { enabled, domain: currentDomain }
      }).catch((error) => {
        console.log('Content script not loaded, change will apply on page reload');
      });
    }
  } catch (error) {
    console.error('Failed to toggle domain:', error);
    showNotification('Failed to update domain setting: ' + error.message, 'error');
    //Revert checkbox
    event.target.checked = !enabled;
  }
}

//Load stats
async function loadStats() {
  try {
    const cacheStats = await sendMessage({ action: 'cache.stats' });
    const storageStats = await sendMessage({ action: 'storage.stats' });

    //Update cache stats (with null guards)
    const cacheSize = document.getElementById('cache-size');
    const cacheEntries = document.getElementById('cache-entries');
    const storageUsed = document.getElementById('storage-used');

    if (cacheSize) cacheSize.textContent = cacheStats.total_size_mb + ' MB';
    if (cacheEntries) cacheEntries.textContent = cacheStats.entries;
    if (storageUsed) storageUsed.textContent = storageStats.total_mb + ' MB';
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
}

//Load current page stats from content script
async function loadPageStats(tab) {
  try {
    if (!tab || !tab.id) return;

    //Query content script for current stats
    const stats = await chrome.tabs.sendMessage(tab.id, {
      action: 'page.getStats'
    }).catch(() => {
      //Content script not loaded or domain disabled
      return null;
    });

    if (stats) {
      document.getElementById('stat-entities').textContent = stats.total || 0;
      document.getElementById('stat-enriched').textContent = stats.enriched || 0;
      document.getElementById('stat-cached').textContent = stats.cached || 0;
    } else {
      //No stats available
      document.getElementById('stat-entities').textContent = '0';
      document.getElementById('stat-enriched').textContent = '0';
      document.getElementById('stat-cached').textContent = '0';
    }
  } catch (error) {
    console.error('Failed to load page stats:', error);
  }
}

//Render settings
async function renderSettings() {
  if (!config) return;

  //Set config values (with null guards)
  const targetOrg = document.getElementById('target-org');
  const cacheTTL = document.getElementById('cache-ttl');
  const cacheSize = document.getElementById('cache-size');

  if (targetOrg) targetOrg.value = config.target_org || '';
  if (cacheTTL) cacheTTL.value = config.cache_ttl_days || 30;
  if (cacheSize) cacheSize.value = config.cache_max_size_mb || 50;

  //Load API keys from encrypted storage
  try {
    secrets = await sendMessage({ action: 'secrets.get' });
    if (secrets) {
      const geminiKey = document.getElementById('gemini-api-key');
      const gtiKey = document.getElementById('gti-api-key');

      if (geminiKey) geminiKey.value = secrets.gemini_api_key || '';
      if (gtiKey) gtiKey.value = secrets.gti_api_key || '';
    }
  } catch (error) {
    console.error('Failed to load API keys:', error);
  }
}

//Save settings
async function saveSettings() {
  try {
    //Get config values
    config.target_org = document.getElementById('target-org').value.trim();
    config.cache_ttl_days = parseInt(document.getElementById('cache-ttl').value);
    config.cache_max_size_mb = parseInt(document.getElementById('cache-size').value);

    //Get API keys
    const geminiKey = document.getElementById('gemini-api-key').value.trim();
    const gtiKey = document.getElementById('gti-api-key').value.trim();

    //Validate
    if (!geminiKey && !gtiKey) {
      showNotification('At least one API key is required', 'error');
      return;
    }

    //Save config
    await sendMessage({ action: 'config.save', data: config });

    //Save API keys to encrypted storage
    const secretsToSave = {};
    if (geminiKey) secretsToSave.gemini_api_key = geminiKey;
    if (gtiKey) secretsToSave.gti_api_key = gtiKey;

    await sendMessage({ action: 'secrets.save', data: secretsToSave });

    showNotification('Settings saved successfully', 'success');
  } catch (error) {
    showNotification('Failed to save settings: ' + error.message, 'error');
  }
}

//Render sources
function renderSources() {
  const container = document.getElementById('sources-list');
  if (!container) return; //Guard: container doesn't exist in current HTML
  container.innerHTML = '';

  if (!config || !config.intel_sources || config.intel_sources.length === 0) {
    container.innerHTML = '<p class="help-text">No intelligence sources configured</p>';
    return;
  }

  for (const source of config.intel_sources) {
    const div = document.createElement('div');
    div.className = 'source-item';
    div.innerHTML = `
      <div class="source-header">
        <span class="source-name">${source.name}</span>
        <span class="source-status status-unknown" id="status-${source.id}">Not tested</span>
      </div>
      <div class="api-key-group">
        <input type="password" id="key-${source.id}" placeholder="API Key" value="${secrets?.[source.id] || ''}">
        <button class="btn-secondary" onclick="toggleKey('${source.id}')">👁</button>
        <button class="btn-secondary" onclick="testSource('${source.id}')">Test</button>
        <button class="btn-primary" onclick="saveSourceKey('${source.id}')">Save</button>
      </div>
    `;
    container.appendChild(div);
  }
}

//Toggle API key visibility
window.toggleKey = function(sourceId) {
  const input = document.getElementById(`key-${sourceId}`);
  input.type = input.type === 'password' ? 'text' : 'password';
};

//Test source connection
window.testSource = async function(sourceId) {
  try {
    const apiKey = document.getElementById(`key-${sourceId}`).value.trim();
    if (!apiKey) {
      showNotification('Enter API key first', 'error');
      return;
    }

    const status = document.getElementById(`status-${sourceId}`);
    status.textContent = 'Testing...';
    status.className = 'source-status status-unknown';

    const result = await sendMessage({
      action: 'secrets.test',
      data: { sourceId, apiKey }
    });

    if (result.valid) {
      status.textContent = 'Valid ✓';
      status.className = 'source-status status-valid';
    } else {
      status.textContent = 'Invalid ✗';
      status.className = 'source-status status-invalid';
    }
  } catch (error) {
    showNotification('Test failed: ' + error.message, 'error');
  }
};

//Save source API key
window.saveSourceKey = async function(sourceId) {
  try {
    const apiKey = document.getElementById(`key-${sourceId}`).value.trim();
    if (!apiKey) {
      showNotification('Enter API key first', 'error');
      return;
    }

    secrets[sourceId] = apiKey;
    await sendMessage({ action: 'secrets.save', data: secrets });
    showNotification('API key saved', 'success');
  } catch (error) {
    showNotification('Failed to save API key: ' + error.message, 'error');
  }
};

//Test Gemini API connection
async function testGeminiAPI() {
  const statusEl = document.getElementById('gemini-status');
  const btn = document.getElementById('test-gemini');

  try {
    btn.disabled = true;
    btn.textContent = 'Testing...';
    statusEl.textContent = 'Testing connection...';
    statusEl.className = 'help-text';

    const result = await sendMessage({ action: 'api.testGemini' });

    if (result.valid) {
      statusEl.textContent = '✓ Connected: ' + (result.message || 'API key valid');
      statusEl.className = 'help-text success';
    } else {
      statusEl.textContent = '✗ Failed: ' + (result.error || 'Invalid API key');
      statusEl.className = 'help-text error';
    }
  } catch (error) {
    statusEl.textContent = '✗ Error: ' + error.message;
    statusEl.className = 'help-text error';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test Gemini Connection';
  }
}

//Test GTI API connection
async function testGTIAPI() {
  const statusEl = document.getElementById('gti-status');
  const btn = document.getElementById('test-gti');

  try {
    btn.disabled = true;
    btn.textContent = 'Testing...';
    statusEl.textContent = 'Testing connection...';
    statusEl.className = 'help-text';

    const result = await sendMessage({ action: 'api.testGTI' });

    if (result.valid) {
      statusEl.textContent = '✓ Connected: ' + (result.message || 'API key valid');
      statusEl.className = 'help-text success';
    } else {
      statusEl.textContent = '✗ Failed: ' + (result.error || 'Invalid API key');
      statusEl.className = 'help-text error';
    }
  } catch (error) {
    statusEl.textContent = '✗ Error: ' + error.message;
    statusEl.className = 'help-text error';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test GTI Connection';
  }
}

//Test all sources
async function testAllSources() {
  const sources = config?.intel_sources || [];
  for (const source of sources) {
    if (secrets[source.id]) {
      await testSource(source.id);
    }
  }
}

//Render pivots
function renderPivots() {
  const container = document.getElementById('pivots-list');
  if (!container) return; //Guard: prevent null reference
  container.innerHTML = '';

  if (!config || !config.pivot_links) {
    container.innerHTML = '<p class="help-text">No pivot links configured</p>';
    return;
  }

  for (const [id, pivot] of Object.entries(config.pivot_links)) {
    const div = document.createElement('div');
    div.className = 'pivot-item';

    const urlPreview = pivot.url_template.length > 60 ? pivot.url_template.substring(0, 60) + '...' : pivot.url_template;

    div.innerHTML = `
      <div class="pivot-header">
        <label class="toggle" style="flex: 1;">
          <input type="checkbox" ${pivot.enabled ? 'checked' : ''} onchange="togglePivot('${id}', this.checked)">
          <span class="pivot-name">${pivot.label}</span>
        </label>
        <div style="display: flex; gap: 6px;">
          <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="editPivot('${id}')">✏️ Edit</button>
          <button class="btn-danger" style="padding: 4px 8px; font-size: 11px;" onclick="deletePivot('${id}')">🗑️</button>
        </div>
      </div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px; font-family: monospace;">${urlPreview}</div>
      <div class="help-text">IOC Types: ${pivot.ioc_types.join(', ')}</div>
    `;
    container.appendChild(div);
  }
}

//Toggle pivot
window.togglePivot = async function(pivotId, enabled) {
  try {
    config.pivot_links[pivotId].enabled = enabled;
    await sendMessage({ action: 'config.save', data: config });
  } catch (error) {
    showNotification('Failed to update pivot: ' + error.message, 'error');
  }
};

//Show pivot form
let editingPivotId = null;

function showPivotForm(pivotId = null) {
  editingPivotId = pivotId;
  const form = document.getElementById('pivot-form');
  form.style.display = 'block';

  if (pivotId) {
    //Edit mode - load existing pivot
    const pivot = config.pivot_links[pivotId];
    document.getElementById('pivot-name').value = pivot.label;
    document.getElementById('pivot-url').value = pivot.url_template;
    document.getElementById('pivot-types').value = pivot.ioc_types.join(', ');
    document.getElementById('pivot-api-key').value = pivot.api_key || '';
    document.getElementById('pivot-api-header').value = pivot.api_header || '';
    document.getElementById('pivot-enabled').checked = pivot.enabled;
  } else {
    //Add mode - clear form
    document.getElementById('pivot-name').value = '';
    document.getElementById('pivot-url').value = '';
    document.getElementById('pivot-types').value = 'ip, domain, url, hash';
    document.getElementById('pivot-api-key').value = '';
    document.getElementById('pivot-api-header').value = '';
    document.getElementById('pivot-enabled').checked = true;
  }

  //Add toggle mask listener for new API key field
  const apiKeyMaskBtn = document.querySelector('#pivot-form .btn-toggle-mask[data-target="pivot-api-key"]');
  if (apiKeyMaskBtn) {
    apiKeyMaskBtn.onclick = toggleMask;
  }
}

function hidePivotForm() {
  editingPivotId = null;
  document.getElementById('pivot-form').style.display = 'none';
}

//Save pivot (add or update)
async function savePivot() {
  try {
    const name = document.getElementById('pivot-name').value.trim();
    const url = document.getElementById('pivot-url').value.trim();
    const types = document.getElementById('pivot-types').value.split(',').map(t => t.trim()).filter(t => t);
    const apiKey = document.getElementById('pivot-api-key').value.trim();
    const apiHeader = document.getElementById('pivot-api-header').value.trim();
    const enabled = document.getElementById('pivot-enabled').checked;

    //Validation
    if (!name) {
      showNotification('Pivot name is required', 'error');
      return;
    }
    if (!url) {
      showNotification('URL template is required', 'error');
      return;
    }
    if (types.length === 0) {
      showNotification('At least one IOC type is required', 'error');
      return;
    }
    if (!url.includes('{{value}}') && !url.includes('{{type}}')) {
      showNotification('URL template must include {{value}} or {{type}} placeholder', 'error');
      return;
    }

    //Create pivot ID from name
    const pivotId = editingPivotId || name.toLowerCase().replace(/[^a-z0-9]/g, '-');

    //Create pivot object
    const pivot = {
      label: name,
      url_template: url,
      ioc_types: types,
      enabled: enabled
    };

    //Add API key fields if provided
    if (apiKey) {
      pivot.api_key = apiKey;
    }
    if (apiHeader) {
      pivot.api_header = apiHeader;
    }

    //Add/update pivot
    if (!config.pivot_links) {
      config.pivot_links = {};
    }
    config.pivot_links[pivotId] = pivot;

    //Save config
    await sendMessage({ action: 'config.save', data: config });

    showNotification(editingPivotId ? 'Pivot updated successfully' : 'Pivot added successfully', 'success');
    hidePivotForm();
    renderPivots();
  } catch (error) {
    showNotification('Failed to save pivot: ' + error.message, 'error');
  }
}

//Edit pivot
window.editPivot = function(pivotId) {
  showPivotForm(pivotId);
};

//Delete pivot
window.deletePivot = async function(pivotId) {
  if (!confirm(`Delete pivot "${config.pivot_links[pivotId].label}"?`)) return;

  try {
    delete config.pivot_links[pivotId];
    await sendMessage({ action: 'config.save', data: config });
    showNotification('Pivot deleted', 'success');
    renderPivots();
  } catch (error) {
    showNotification('Failed to delete pivot: ' + error.message, 'error');
  }
};

//Open Service Worker Console
function openServiceWorker() {
  chrome.tabs.create({ url: 'chrome://extensions/?id=' + chrome.runtime.id });
  showNotification('Extensions page opened - click "service worker" link', 'success');
}

//Render enabled domains
async function renderDomains() {
  const container = document.getElementById('domains-list');
  const countEl = document.getElementById('domain-count');

  if (!container || !countEl) return; //Guard: prevent null reference

  try {
    const result = await chrome.storage.local.get(['enabled_domains']);
    const domains = result.enabled_domains || [];

    countEl.textContent = domains.length;

    if (domains.length === 0) {
      container.innerHTML = '<div class="log-empty">No domains enabled yet</div>';
      return;
    }

    //Sort domains alphabetically
    domains.sort();

    container.innerHTML = domains.map(domain => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px; background: var(--bg-secondary); border-radius: 4px; margin-bottom: 6px;">
        <span style="font-family: monospace; font-size: 11px; font-weight: 500;">${domain}</span>
        <button class="btn-danger" style="padding: 3px 8px; font-size: 10px;" onclick="removeDomain('${domain}')">✖</button>
      </div>
    `).join('');
  } catch (error) {
    console.error('Failed to load domains:', error);
    container.innerHTML = '<div class="log-empty">Failed to load domains</div>';
  }
}

//Remove domain from whitelist
window.removeDomain = async function(domain) {
  try {
    const result = await chrome.storage.local.get(['enabled_domains']);
    let domains = result.enabled_domains || [];

    domains = domains.filter(d => d !== domain);

    await chrome.storage.local.set({ enabled_domains: domains });
    showNotification(`Removed ${domain}`, 'success');
    await renderDomains();
  } catch (error) {
    showNotification('Failed to remove domain: ' + error.message, 'error');
  }
};

//Export domains as JSON
async function exportDomains() {
  try {
    const result = await chrome.storage.local.get(['enabled_domains']);
    const domains = result.enabled_domains || [];

    const json = JSON.stringify(domains, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `optic-ioc-domains-${Date.now()}.json`;
    a.click();

    URL.revokeObjectURL(url);
    showNotification(`Exported ${domains.length} domains`, 'success');
  } catch (error) {
    showNotification('Failed to export: ' + error.message, 'error');
  }
}

//Import domains from JSON
async function importDomains() {
  try {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'application/json';

    input.onchange = async (e) => {
      try {
        const file = e.target.files[0];
        if (!file) return;

        const text = await file.text();
        const imported = JSON.parse(text);

        if (!Array.isArray(imported)) {
          throw new Error('Invalid format - expected JSON array');
        }

        //Merge with existing domains (no duplicates)
        const result = await chrome.storage.local.get(['enabled_domains']);
        const existing = result.enabled_domains || [];
        const merged = [...new Set([...existing, ...imported])];

        await chrome.storage.local.set({ enabled_domains: merged });
        showNotification(`Imported ${imported.length} domains (${merged.length} total)`, 'success');
        await renderDomains();
      } catch (error) {
        showNotification('Failed to import: ' + error.message, 'error');
      }
    };

    input.click();
  } catch (error) {
    showNotification('Failed to import: ' + error.message, 'error');
  }
}

//Clear all domains
async function clearDomains() {
  if (!confirm('Remove all enabled domains? This will disable Optic IOC on all sites.')) return;

  try {
    await chrome.storage.local.set({ enabled_domains: [] });
    showNotification('All domains cleared', 'success');
    await renderDomains();
  } catch (error) {
    showNotification('Failed to clear domains: ' + error.message, 'error');
  }
}

//Clear cache
async function clearCache() {
  if (!confirm('Clear all cached enrichments?')) return;

  try {
    await sendMessage({ action: 'cache.clear' });
    showNotification('Cache cleared', 'success');
    await loadStats();
  } catch (error) {
    showNotification('Failed to clear cache: ' + error.message, 'error');
  }
}

//Refresh page analysis (Phase 3)
async function refreshPage() {
  try {
    //Get current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.id) {
      showNotification('No active tab found', 'error');
      return;
    }

    //Send refresh message to content script
    const response = await chrome.tabs.sendMessage(tab.id, {
      action: 'page.refresh',
      data: { bypassCache: false } //can add checkbox for cache bypass
    });

    if (response && response.success) {
      showNotification(`Analysis refreshed - found ${response.iocs} IOCs`, 'success');
      //Reload stats
      await loadStats();
    } else {
      showNotification('Refresh failed: ' + (response?.error || 'Unknown error'), 'error');
    }
  } catch (error) {
    console.error('Refresh error:', error);
    showNotification('Refresh failed: ' + error.message, 'error');
  }
}

//Export config
async function exportConfig() {
  try {
    const password = prompt('Enter password to encrypt export (min 8 chars):');
    if (!password || password.length < 8) {
      showNotification('Password must be at least 8 characters', 'error');
      return;
    }

    const json = await sendMessage({ action: 'config.export', data: { password } });

    //Download file
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `optic-ioc-config-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);

    showNotification('Configuration exported', 'success');
  } catch (error) {
    showNotification('Export failed: ' + error.message, 'error');
  }
}

//Import config
async function importConfig() {
  try {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';

    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const password = prompt('Enter decryption password:');
      if (!password) return;

      const json = await file.text();

      await sendMessage({
        action: 'config.import',
        data: { json, password }
      });

      showNotification('Configuration imported', 'success');
      setTimeout(() => location.reload(), 1000);
    };

    input.click();
  } catch (error) {
    showNotification('Import failed: ' + error.message, 'error');
  }
}

//Reset config
async function resetConfig() {
  if (!confirm('Reset all settings to defaults? This will clear your API keys.')) return;

  try {
    await sendMessage({ action: 'config.reset' });
    showNotification('Configuration reset', 'success');
    setTimeout(() => location.reload(), 1000);
  } catch (error) {
    showNotification('Reset failed: ' + error.message, 'error');
  }
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

//Show notification
function showNotification(message, type = 'info') {
  //TODO: Add toast notification UI
  console.log(`[${type.toUpperCase()}] ${message}`);
  alert(message); //temporary
}


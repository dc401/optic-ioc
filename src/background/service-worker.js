//Optic IOC - Service Worker (Main Background Script)
//Central orchestrator for extension functionality

//Import all managers
importScripts(
  '../lib/constants.js',
  '../lib/crypto-utils.js',
  '../lib/ioc-patterns.js',
  '../lib/url-builder.js',
  '../lib/security-validator.js',
  'storage-manager.js',
  'rate-limiter.js',
  'cache-manager.js',
  'context-menu.js',
  'gemini-client.js',
  'gti-client.js',
  'gti-submission-manager.js',
  'api-orchestrator.js'
);

//Global state
let config = null;
let storageManager = null;
let geminiClient = null;
let gtiClient = null;
let apiOrchestrator = null;
//Note: cryptoManager, urlBuilder, rateLimiterManager, cacheManager, contextMenuManager
//are all instantiated in their respective imported files as singletons

//Initialize on install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('Optic IOC installed:', details.reason);

  try {
    //Initialize storage manager
    storageManager = new StorageManager(cryptoManager);

    //Load or create default config
    config = await storageManager.loadConfig();

    //Load default sources and pivots if first install or if empty
    if (details.reason === 'install' || !config.pivot_links || Object.keys(config.pivot_links).length === 0) {
      await initializeDefaults();
      //Reload config after defaults loaded
      config = await storageManager.loadConfig();
    }

    //Initialize context menus
    await contextMenuManager.initialize(config);

    //Load cache from storage
    await cacheManager.loadFromStorage();

//Initialize API clients (now that storageManager exists)
    geminiClient = new GeminiClient(storageManager);
    gtiClient = new GTIClient(storageManager);
    apiOrchestrator = new APIOrchestrator(storageManager, cacheManager, rateLimiterManager);

    await geminiClient.initialize();
    await gtiClient.initialize();
    apiOrchestrator.initialize(geminiClient, gtiClient);

    //Initialize GTI submission manager
    await gtiSubmissionManager.initialize();

    //Set up periodic cache cleanup
    chrome.alarms.create('cache-cleanup', { periodInMinutes: 60 });

    //Set up periodic API testing (every 15 minutes)
    chrome.alarms.create('api-health-check', { periodInMinutes: 15 });

    console.log('Optic IOC initialized successfully');
  } catch (error) {
    console.error('Initialization error:', error);
  }
});

//Initialize default configuration
async function initializeDefaults() {
  try {
    //Load default sources
    const sourcesResponse = await fetch(chrome.runtime.getURL('config/default-sources.json'));
    const defaultSources = await sourcesResponse.json();

    //Load default pivots
    const pivotsResponse = await fetch(chrome.runtime.getURL('config/default-pivots.json'));
    const defaultPivots = await pivotsResponse.json();

    //Merge with existing config
    config.intel_sources = defaultSources;
    config.pivot_links = defaultPivots;

    //Save updated config
    await storageManager.saveConfig(config);

    console.log('Default configuration initialized');
  } catch (error) {
    console.error('Failed to initialize defaults:', error);
  }
}

//Handle service worker startup
chrome.runtime.onStartup.addListener(async () => {
  console.log('Optic IOC service worker started');

  try {
    //Reinitialize
    storageManager = new StorageManager(cryptoManager);
    config = await storageManager.loadConfig();
    await contextMenuManager.initialize(config);
    await cacheManager.loadFromStorage();

    //Reinitialize API clients
    geminiClient = new GeminiClient(storageManager);
    gtiClient = new GTIClient(storageManager);
    apiOrchestrator = new APIOrchestrator(storageManager, cacheManager, rateLimiterManager);

    await geminiClient.initialize();
    await gtiClient.initialize();
    apiOrchestrator.initialize(geminiClient, gtiClient);

    //FIXED: Initialize GTI submission manager
    await gtiSubmissionManager.initialize();
  } catch (error) {
    console.error('Startup error:', error);
  }
});

//Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  contextMenuManager.handleClick(info, tab);
});

//Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(error => {
      console.error('Message handler error:', error);
      sendResponse({ error: error.message });
    });
  return true; //async response
});

//Ensure service worker is initialized
async function ensureInitialized() {
  if (!storageManager) {
    console.log('Lazy initializing service worker...');
    storageManager = new StorageManager(cryptoManager);
    config = await storageManager.loadConfig();
    await contextMenuManager.initialize(config);
    await cacheManager.loadFromStorage();

    geminiClient = new GeminiClient(storageManager);
    gtiClient = new GTIClient(storageManager);
    apiOrchestrator = new APIOrchestrator(storageManager, cacheManager, rateLimiterManager);

    await geminiClient.initialize();
    await gtiClient.initialize();
    apiOrchestrator.initialize(geminiClient, gtiClient);

    console.log('Service worker initialized');
  }
}

//Message handler
async function handleMessage(message, sender) {
  //Ensure initialized
  await ensureInitialized();

  const { action, data } = message;

  switch (action) {
    //Configuration
    case 'config.get':
      return await storageManager.loadConfig();

    case 'config.save':
      await storageManager.saveConfig(data);
      config = data;
      await contextMenuManager.initialize(config);
      urlBuilder.setConfig(config);
      return { success: true };

    case 'config.export':
      return await storageManager.exportConfig(data.password);

    case 'config.import':
      await storageManager.importConfig(data.json, data.password);
      config = await storageManager.loadConfig();
      return { success: true };

    case 'config.reset':
      await storageManager.clearAll();
      config = storageManager.getDefaultConfig();
      await storageManager.saveConfig(config);
      await initializeDefaults();
      return { success: true };

    //Secrets management
    case 'secrets.save':
      return await storageManager.saveSecrets(data);

    case 'secrets.get':
      return await storageManager.loadSecrets();

    case 'secrets.test':
      //Test API key for specific source
      return await testAPIKey(data.sourceId, data.apiKey);

    //Cache management
    case 'cache.get':
      return await cacheManager.get(data.iocType, data.iocValue);

    case 'cache.set':
      await cacheManager.set(data.iocType, data.iocValue, data.enrichment);
      return { success: true };

    case 'cache.clear':
      await cacheManager.clear();
      return { success: true };

    case 'cache.stats':
      return cacheManager.getStats();

    //Rate limiting
    case 'rate.stats':
      return rateLimiterManager.getStats();

    case 'rate.reset':
      if (data.sourceId) {
        rateLimiterManager.reset(data.sourceId);
      } else {
        rateLimiterManager.resetAll();
      }
      return { success: true };

    //Storage stats
    case 'storage.stats':
      return await storageManager.getStorageStats();

    //Extract IOCs from text
    case 'ioc.extract':
      return { iocs: extractIOCs(data.text) };

    //Build pivot URLs
    case 'pivot.build':
      const pivotURLs = urlBuilder.buildPivotURLs(data.ioc, config.pivot_links);
      return { urls: pivotURLs };

    //Context menu update
    case 'context.update':
      await contextMenuManager.updateMenus(data.selection);
      return { success: true };

    //IOC Enrichment
    case 'ioc.enrich':
      return await apiOrchestrator.enrichIOC(
        data.ioc_type,
        data.ioc_value,
        config.target_org || ''
      );

    case 'ioc.enrichBatch':
      return await apiOrchestrator.enrichBatch(
        data.iocs,
        config.target_org || ''
      );

    //Aggregate IOC summary (75% threshold analysis)
    case 'ioc.aggregateSummary':
      return await geminiClient.generateAggregateSummary(
        data.iocs,
        data.pageUrl,
        config.target_org || '',
        data.enrichedCount,
        data.totalCount
      );

    //Page content analysis (when no hard IOCs found)
    case 'page.analyze':
      return await geminiClient.analyzePageContent(
        data.pageText,
        config.target_org || ''
      );

    //Gemini prompt preview
    case 'gemini.getPrompts':
      return await geminiClient.getStoredPrompts();

    //API Testing
    case 'api.testGemini':
      return await geminiClient.testConnection();

    case 'api.testGTI':
      return await gtiClient.testConnection();

    case 'api.getHealthStatus':
      const healthResult = await chrome.storage.local.get(['api_health_status']);
      return healthResult.api_health_status || null;

    //GTI Submissions
    case 'gti.submit':
      return await gtiSubmissionManager.addSubmission(
        data.ioc_type,
        data.ioc_value,
        data.notes || ''
      );

    case 'gti.getSubmissions':
      return await gtiSubmissionManager.getSubmissions();

    case 'gti.removeSubmission':
      return await gtiSubmissionManager.removeSubmission(data.ioc_value, data.ioc_type);

    case 'gti.exportCSV':
      return await gtiSubmissionManager.exportCSV();

    case 'gti.importCSV':
      return await gtiSubmissionManager.importCSV(data.csv);

    case 'gti.clearSubmissions':
      return await gtiSubmissionManager.clearAll();

    case 'gti.stats':
      return await gtiSubmissionManager.getStats();

    default:
      throw new Error('Unknown action: ' + action);
  }
}

//Test API key for source
async function testAPIKey(sourceId, apiKey) {
  try {
    //Find source config
    const source = config.intel_sources?.find(s => s.id === sourceId);
    if (!source) {
      return { valid: false, error: 'Source not found' };
    }

    //Build test request based on source
    let testUrl = '';
    let testHeaders = {};

    if (sourceId === 'gti') {
      testUrl = 'https://www.virustotal.com/api/v3/users/current';
      testHeaders = { 'x-apikey': apiKey };
    } else if (sourceId === 'shodan') {
      testUrl = 'https://api.shodan.io/api-info?key=' + apiKey;
    } else if (sourceId === 'otx') {
      testUrl = 'https://otx.alienvault.com/api/v1/user/me';
      testHeaders = { 'X-OTX-API-KEY': apiKey };
    } else if (sourceId === 'urlscan') {
      testUrl = 'https://urlscan.io/user/quotas/';
      testHeaders = { 'API-Key': apiKey };
    } else {
      return { valid: false, error: 'API key testing not implemented for this source' };
    }

    //Make test request
    const response = await fetch(testUrl, { headers: testHeaders });

    if (response.ok) {
      return { valid: true, status: response.status };
    } else {
      return { valid: false, status: response.status, error: response.statusText };
    }
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

//Periodic API health check
async function performAPIHealthCheck() {
  try {
    console.log('[API-HEALTH] Running periodic health check...');
    await ensureInitialized();

    const results = {
      timestamp: new Date().toISOString(),
      gemini: { status: 'unknown', error: null },
      gti: { status: 'unknown', error: null }
    };

    //Test Gemini API
    try {
      const geminiResult = await geminiClient.testConnection();
      results.gemini.status = geminiResult.valid ? 'healthy' : 'failed';
      results.gemini.error = geminiResult.error || null;
    } catch (error) {
      results.gemini.status = 'failed';
      results.gemini.error = error.message;
    }

    //Test GTI API
    try {
      const gtiResult = await gtiClient.testConnection();
      results.gti.status = gtiResult.valid ? 'healthy' : 'failed';
      results.gti.error = gtiResult.error || null;
    } catch (error) {
      results.gti.status = 'failed';
      results.gti.error = error.message;
    }

    //Store health status
    await chrome.storage.local.set({ api_health_status: results });

    console.log('[API-HEALTH] Check complete:', results);

    //Log warnings and send notifications if any API failed
    const hasFailures = results.gemini.status === 'failed' || results.gti.status === 'failed';

    if (results.gemini.status === 'failed') {
      console.warn('[API-HEALTH] Gemini API unhealthy:', results.gemini.error);
    }
    if (results.gti.status === 'failed') {
      console.warn('[API-HEALTH] GTI API unhealthy:', results.gti.error);
    }

    //Send notification to all tabs if any API failed
    if (hasFailures) {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        try {
          await chrome.tabs.sendMessage(tab.id, {
            action: 'api.healthAlert',
            data: results
          });
        } catch (error) {
          //Tab might not have content script, ignore
        }
      }
    }

    return results;
  } catch (error) {
    console.error('[API-HEALTH] Health check failed:', error);
    return null;
  }
}

//Handle alarms (periodic tasks)
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'cache-cleanup') {
    //Clear expired cache entries
    await cacheManager.clearExpired();
  } else if (alarm.name === 'api-health-check') {
    //Test API connectivity every 15 minutes
    await performAPIHealthCheck();
  }
});

//Handle tab activation (for context menu updates)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  //Context menus persist across tabs, no action needed
});

//Clean shutdown
chrome.runtime.onSuspend.addListener(() => {
  console.log('Service worker suspending, clearing memory cache');
  storageManager?.clearMemoryCache();
});

console.log('Optic IOC service worker loaded');

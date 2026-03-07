//Optic IOC - Context Menu Handler
//Right-click context menu for IOC pivoting
//Dynamically generates menu based on selected text and configured pivot links

class ContextMenuManager {
  constructor() {
    this.initialized = false;
    this.config = null;
    //REMOVED: lastSelection (never read)
  }

  //Initialize context menus
  async initialize(config) {
    this.config = config;

    try {
      //Remove existing menus using callback
      await new Promise((resolve) => {
        chrome.contextMenus.removeAll(() => {
          if (chrome.runtime.lastError) {
            console.warn('Error removing menus:', chrome.runtime.lastError);
          }
          resolve();
        });
      });

      //Create root menu
      await new Promise((resolve) => {
        chrome.contextMenus.create({
          id: OPTIC_CONSTANTS.CONTEXT_MENU.ROOT,
          title: 'Optic IOC',
          contexts: ['selection']
        }, () => {
          if (chrome.runtime.lastError) {
            console.error('Error creating root menu:', chrome.runtime.lastError);
          }
          resolve();
        });
      });

      //Create submenus for all enabled pivot links
      const pivotLinks = this.config?.pivot_links || {};
      const sortedPivots = Object.entries(pivotLinks)
        .filter(([id, pivot]) => pivot.enabled !== false)
        .sort((a, b) => (a[1].order || 999) - (b[1].order || 999));

      for (const [id, pivot] of sortedPivots) {
        await new Promise((resolve) => {
          chrome.contextMenus.create({
            id: OPTIC_CONSTANTS.CONTEXT_MENU.PREFIX + id,
            parentId: OPTIC_CONSTANTS.CONTEXT_MENU.ROOT,
            title: pivot.label || id,
            contexts: ['selection']
          }, () => {
            if (chrome.runtime.lastError) {
              console.error(`Error creating pivot menu ${id}:`, chrome.runtime.lastError);
            }
            resolve();
          });
        });
      }

      console.log(`✓ Created context menu with ${sortedPivots.length} pivot links + GTI submit`);
      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize context menus:', error);
    }
  }

  //Update menus when selection changes (SIMPLIFIED - no dynamic updates)
  async updateMenus(selectionText) {
    //REMOVED: lastSelection storage (never read)
    //Don't recreate menus - keep them static to avoid errors
  }

  //Handle menu click
  async handleClick(info, tab) {
    const menuId = info.menuItemId;

    //Extract action ID
    if (!menuId.startsWith(OPTIC_CONSTANTS.CONTEXT_MENU.PREFIX)) {
      return;
    }

    const actionId = menuId.replace(OPTIC_CONSTANTS.CONTEXT_MENU.PREFIX, '');

    //Get selection
    const selectionText = info.selectionText;
    if (!selectionText) {
      console.log('[CONTEXT-MENU] No selection text');
      return;
    }

    console.log('[CONTEXT-MENU] Selection:', selectionText, 'Action:', actionId);

    //Try to get IOC info from clicked element (if highlight has data attributes)
    //Send message to content script to get clicked element's data
    let ioc = null;
    try {
      const clickedData = await chrome.tabs.sendMessage(tab.id, {
        action: 'getClickedIOC',
        data: { selection: selectionText }
      });

      if (clickedData && clickedData.type && clickedData.value) {
        console.log('[CONTEXT-MENU] Got IOC from clicked element:', clickedData);
        ioc = clickedData;
      }
    } catch (error) {
      console.log('[CONTEXT-MENU] Could not get clicked element data, falling back to extraction');
    }

    //Fallback: Detect IOC from selection text
    if (!ioc) {
      const iocs = extractIOCs(selectionText);
      if (iocs.length === 0) {
        console.log('[CONTEXT-MENU] No IOC detected in selection:', selectionText);
        return;
      }
      ioc = iocs[0];
      console.log('[CONTEXT-MENU] Extracted IOC from selection:', ioc);
    }

    //Handle pivot links
    const pivotConfig = this.config.pivot_links?.[actionId];
    if (!pivotConfig) {
      console.error('Pivot config not found:', actionId);
      return;
    }

    //Build URL
    const url = urlBuilder.buildURL(
      pivotConfig.url_template,
      ioc.type,
      ioc.value,
      pivotConfig.type_mapping
    );

    if (!url) {
      console.error('Failed to build pivot URL');
      return;
    }

    //Open in new tab
    chrome.tabs.create({ url: url, active: true });
  }

}

//Export singleton
const contextMenuManager = new ContextMenuManager();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ContextMenuManager, contextMenuManager };
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.ContextMenuManager = ContextMenuManager;
  self.contextMenuManager = contextMenuManager;
}

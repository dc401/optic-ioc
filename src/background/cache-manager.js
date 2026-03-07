//Optic IOC - Cache Manager
//LRU cache with size limits and TTL
//Stores enrichment data to reduce API calls and improve performance

class CacheManager {
  constructor(maxSizeMB = 50, maxAgeDays = 30) {
    this.maxSizeBytes = maxSizeMB * 1024 * 1024;
    this.maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
    this.cache = new Map(); //key -> { data, timestamp, size, accessed }
    this.totalSize = 0;
    this.persistTimer = null; //PERFORMANCE: Debounce timer for persistence
  }

  //Generate cache key from IOC
  getCacheKey(iocType, iocValue) {
    return `${iocType}:${iocValue.toLowerCase()}`;
  }

  //Get item from cache
  //FIXED: Return data directly instead of wrapping in object
  async get(iocType, iocValue) {
    const key = this.getCacheKey(iocType, iocValue);
    const item = this.cache.get(key);

    if (!item) {
      return null;
    }

    //Check if expired
    const age = Date.now() - item.timestamp;
    if (age > this.maxAgeMs) {
      this.cache.delete(key);
      this.totalSize -= item.size;
      return null;
    }

    //Update access time (for LRU)
    item.accessed = Date.now();

    //Return enrichment data directly
    return item.data;
  }

  //Set item in cache
  async set(iocType, iocValue, data) {
    const key = this.getCacheKey(iocType, iocValue);

    //Estimate size
    const size = this.estimateSize(data);

    //Check if adding would exceed limit
    if (this.totalSize + size > this.maxSizeBytes) {
      await this.evictLRU(size);
    }

    //Remove old entry if exists
    const existing = this.cache.get(key);
    if (existing) {
      this.totalSize -= existing.size;
    }

    //Add to cache
    const item = {
      data: data,
      timestamp: Date.now(),
      accessed: Date.now(),
      size: size
    };

    this.cache.set(key, item);
    this.totalSize += size;

    //Persist to storage
    await this.persistToStorage();
  }

  //Evict least recently used items
  async evictLRU(neededSize) {
    if (this.cache.size === 0) return;

    //Sort by access time (oldest first)
    const sorted = Array.from(this.cache.entries())
      .sort((a, b) => a[1].accessed - b[1].accessed);

    let freedSize = 0;
    const toDelete = [];

    for (const [key, item] of sorted) {
      toDelete.push(key);
      freedSize += item.size;

      //Stop if we've freed enough space
      if (this.totalSize - freedSize + neededSize <= this.maxSizeBytes) {
        break;
      }
    }

    //Delete items
    for (const key of toDelete) {
      const item = this.cache.get(key);
      this.cache.delete(key);
      this.totalSize -= item.size;
    }

    console.log(`Cache evicted ${toDelete.length} items, freed ${this.formatBytes(freedSize)}`);
  }

  //Clear all cache
  async clear() {
    this.cache.clear();
    this.totalSize = 0;
    await this.persistToStorage();
  }

  //Clear expired entries
  async clearExpired() {
    const now = Date.now();
    let cleared = 0;

    for (const [key, item] of this.cache.entries()) {
      if (now - item.timestamp > this.maxAgeMs) {
        this.cache.delete(key);
        this.totalSize -= item.size;
        cleared++;
      }
    }

    if (cleared > 0) {
      console.log(`Cache cleared ${cleared} expired entries`);
      await this.persistToStorage();
    }
  }

  //Estimate object size in bytes
  estimateSize(obj) {
    try {
      const json = JSON.stringify(obj);
      return new Blob([json]).size;
    } catch {
      return 1024; //default 1KB if can't estimate
    }
  }

  //Format age for display
  formatAge(ageMs) {
    const seconds = Math.floor(ageMs / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return `${seconds}s ago`;
  }

  //Format bytes for display
  formatBytes(bytes) {
    const mb = bytes / 1024 / 1024;
    if (mb >= 1) return `${mb.toFixed(2)} MB`;
    const kb = bytes / 1024;
    return `${kb.toFixed(2)} KB`;
  }

  //Get cache statistics
  getStats() {
    return {
      entries: this.cache.size,
      total_size_bytes: this.totalSize,
      total_size_mb: (this.totalSize / 1024 / 1024).toFixed(2),
      max_size_mb: (this.maxSizeBytes / 1024 / 1024).toFixed(2),
      max_age_days: (this.maxAgeMs / 1000 / 60 / 60 / 24).toFixed(0),
      usage_percent: ((this.totalSize / this.maxSizeBytes) * 100).toFixed(1)
    };
  }

  //Persist cache to chrome.storage.local
  //PERFORMANCE: Debounced to prevent excessive storage writes
  async persistToStorage() {
    //Clear existing timer
    if (this.persistTimer) {
      clearTimeout(this.persistTimer);
    }

    //Debounce: persist max once per 5 seconds
    this.persistTimer = setTimeout(async () => {
      try {
        //Convert Map to object for storage
        const cacheData = {};
        for (const [key, item] of this.cache.entries()) {
          cacheData[key] = item;
        }

        const metadata = {
          total_size_bytes: this.totalSize,
          entry_count: this.cache.size,
          last_persist: Date.now()
        };

        await chrome.storage.local.set({
          [OPTIC_CONSTANTS.STORAGE_KEYS.CACHE]: cacheData,
          [OPTIC_CONSTANTS.STORAGE_KEYS.CACHE_META]: metadata
        });

        this.persistTimer = null;
      } catch (error) {
        console.error('Failed to persist cache:', error);
        this.persistTimer = null; //FIXED: Clear timer on error too
      }
    }, 5000); //5 second debounce
  }

  //Load cache from chrome.storage.local
  async loadFromStorage() {
    try {
      const result = await chrome.storage.local.get([
        OPTIC_CONSTANTS.STORAGE_KEYS.CACHE,
        OPTIC_CONSTANTS.STORAGE_KEYS.CACHE_META
      ]);

      const cacheData = result[OPTIC_CONSTANTS.STORAGE_KEYS.CACHE];
      const metadata = result[OPTIC_CONSTANTS.STORAGE_KEYS.CACHE_META];

      if (cacheData) {
        //Convert object back to Map
        this.cache.clear();
        for (const [key, item] of Object.entries(cacheData)) {
          this.cache.set(key, item);
        }
      }

      if (metadata) {
        this.totalSize = metadata.total_size_bytes || 0;
      }

      //Clear expired entries on load
      await this.clearExpired();

      console.log('Cache loaded:', this.getStats());
    } catch (error) {
      console.error('Failed to load cache:', error);
    }
  }

  //Check if cache contains key
  has(iocType, iocValue) {
    const key = this.getCacheKey(iocType, iocValue);
    return this.cache.has(key);
  }

  //Delete specific entry
  delete(iocType, iocValue) {
    const key = this.getCacheKey(iocType, iocValue);
    const item = this.cache.get(key);
    if (item) {
      this.cache.delete(key);
      this.totalSize -= item.size;
      return true;
    }
    return false;
  }
}

//Export singleton
const cacheManager = new CacheManager(
  OPTIC_CONSTANTS.PERFORMANCE.CACHE_MAX_SIZE_MB,
  OPTIC_CONSTANTS.PERFORMANCE.CACHE_TTL_DAYS
);

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CacheManager, cacheManager };
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.CacheManager = CacheManager;
  self.cacheManager = cacheManager;
}

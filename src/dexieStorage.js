import Dexie from 'dexie';
import LZString from 'lz-string';

const CONFIG = {
  STORAGE: {
    DB_NAME: 'GurftronCoreDB',
    DB_VERSION: 6,
    STORES: {
      THREATS: 'threats',
      WHITELIST: 'whitelist',
      ERRORS: 'errors',
      USERS: 'users',
      METRICS: 'metrics'
    },
    MAX_COMPRESSED_SIZE: 1024 * 1024
  },
  NATIVE_HOST: 'com.gurftron.server',
  DOMAIN_INFO_CACHE_TTL: 7 * 24 * 60 * 60 * 1000
};

class CryptoUtils {
  static async generateHash(data) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify(data)));
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

class DexieStorageAdapter {
  constructor() {
    this.db = null;
  }

  async initialize() {
    this.db = new Dexie(CONFIG.STORAGE.DB_NAME);
    // Define stores similar to original schema. key is 'id'
    this.db.version(CONFIG.STORAGE.DB_VERSION).stores({
      [CONFIG.STORAGE.STORES.THREATS]: 'id, timestamp, hash, threatType, severity, url, contentHash',
      [CONFIG.STORAGE.STORES.WHITELIST]: 'id, timestamp, status, url',
      [CONFIG.STORAGE.STORES.ERRORS]: 'id, timestamp, errorType',
      [CONFIG.STORAGE.STORES.USERS]: 'id, timestamp',
      [CONFIG.STORAGE.STORES.METRICS]: 'date, timestamp'
    });

    // Open DB
    await this.db.open();
    return true;
  }

  async save(store, key, data, metadata = {}) {
    try {
      const compressedData = LZString.compressToUTF16(JSON.stringify(data));
      if (compressedData.length * 2 > CONFIG.STORAGE.MAX_COMPRESSED_SIZE) {
        throw new Error(`Compressed data exceeds ${CONFIG.STORAGE.MAX_COMPRESSED_SIZE} bytes`);
      }

      const record = {
        id: key,
        data: compressedData,
        hash: await CryptoUtils.generateHash(data),
        timestamp: Date.now(),
        compressed: true,
        ...metadata
      };

      await this.db.table(store).put(record);
      return record.hash;
    } catch (error) {
      console.error('Dexie save failed:', error);
      throw error;
    }
  }

  async get(store, key) {
    try {
      const result = await this.db.table(store).get(key);
      if (!result) return null;
      return result.compressed ? JSON.parse(LZString.decompressFromUTF16(result.data)) : result.data;
    } catch (error) {
      console.error('Dexie get failed:', error);
      return null;
    }
  }

  async query(store, filter = {}) {
    try {
      const table = this.db.table(store);
      let collection = table.toCollection();

      // Simple index-based filtering where possible
      if (filter.index && typeof filter.value !== 'undefined') {
        try {
          collection = table.where(filter.index).equals(filter.value);
        } catch (e) {
          // fallback to full scan
          collection = table.toCollection();
        }
      }

      const results = await collection.limit(10000).toArray();
      // Decompress and apply additional filter predicates
      const mapped = results.map(r => ({ ...r, data: r.compressed ? JSON.parse(LZString.decompressFromUTF16(r.data)) : r.data }));

      // Apply generic predicate checks similar to matchesFilter
      const filtered = mapped.filter(record => {
        if (filter.minTimestamp && record.timestamp < filter.minTimestamp) return false;
        if (filter.maxTimestamp && record.timestamp > filter.maxTimestamp) return false;
        if (filter.threatType && record.threatType !== filter.threatType) return false;
        if (filter.severity && record.severity !== filter.severity) return false;
        if (filter.url && record.url !== filter.url) return false;
        if (filter.contentHash && record.contentHash !== filter.contentHash) return false;
        if (filter.domain && record.domain !== filter.domain) return false;
        if (filter.country && record.country !== filter.country) return false;
        return true;
      });

      return filtered;
    } catch (error) {
      console.error('Dexie query failed:', error);
      return [];
    }
  }

  async getAllKeys(store) {
    try {
      const keys = await this.db.table(store).toCollection().primaryKeys();
      return keys;
    } catch (error) {
      console.error('Dexie getAllKeys failed:', error);
      return [];
    }
  }

  async logError(errorType, message) {
    try {
      const errorId = await CryptoUtils.generateHash({ errorType, message, timestamp: Date.now() });
      await this.save(CONFIG.STORAGE.STORES.ERRORS, errorId, { errorType, message, timestamp: Date.now() }, { errorType });
    } catch (e) {
      console.error('Dexie logError failed:', e);
    }
  }

  async updateMetrics(metricsData) {
    try {
      const now = new Date();
      const dateKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
      
      // Get existing metrics for today
      const existing = await this.db.table(CONFIG.STORAGE.STORES.METRICS).get(dateKey);
      
      const updatedMetrics = {
        date: dateKey,
        timestamp: Date.now(),
        scans: (existing?.scans || 0) + (metricsData.scans || 0),
        threatsDetected: (existing?.threatsDetected || 0) + (metricsData.threatsDetected || 0),
        llmCalls: (existing?.llmCalls || 0) + (metricsData.llmCalls || 0)
      };
      
      await this.db.table(CONFIG.STORAGE.STORES.METRICS).put(updatedMetrics);
      return updatedMetrics;
    } catch (e) {
      console.error('Dexie updateMetrics failed:', e);
      throw e;
    }
  }

  async getMetrics(dateKey = null) {
    try {
      if (dateKey) {
        return await this.db.table(CONFIG.STORAGE.STORES.METRICS).get(dateKey);
      }
      
      // Get today's metrics if no date specified
      const now = new Date();
      const todayKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
      return await this.db.table(CONFIG.STORAGE.STORES.METRICS).get(todayKey);
    } catch (e) {
      console.error('Dexie getMetrics failed:', e);
      return null;
    }
  }
}

export { DexieStorageAdapter, CONFIG }
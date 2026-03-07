//Optic IOC - GTI Submission Manager
//Manages local storage of IOC submissions for GTI custom lists
//Stores as CSV-formatted data in chrome.storage.local

class GTISubmissionManager {
  constructor() {
    this.listName = 'optic-ioc';
    this.storageKey = 'gti_submissions';
    this.maxEntries = 50000; //max submissions to keep
  }

  //Initialize manager (load existing submissions)
  async initialize() {
    try {
      const result = await chrome.storage.local.get([this.storageKey]);
      const submissions = result[this.storageKey] || [];
      console.log(`GTI Submission Manager: Loaded ${submissions.length} submissions`);
      return submissions.length;
    } catch (error) {
      console.error('Failed to initialize GTI submission manager:', error);
      return 0;
    }
  }

  //Add IOC to submission list
  async addSubmission(iocType, iocValue, notes = '') {
    try {
      console.log(`[GTI-SUBMIT] Adding ${iocType}: ${iocValue}`);
      console.log(`[GTI-SUBMIT] Storage key: ${this.storageKey}`);

      //Load existing submissions
      const result = await chrome.storage.local.get([this.storageKey]);
      let submissions = result[this.storageKey] || [];

      console.log(`[GTI-SUBMIT] Existing submissions: ${submissions.length}`);

      //Check for duplicate
      const duplicate = submissions.find(s => s.type === iocType && s.value === iocValue);
      if (duplicate) {
        console.log(`[GTI-SUBMIT] Duplicate found: ${iocValue} already in list (added ${duplicate.timestamp})`);
        return { success: false, error: 'Already in submission list', existing: duplicate };
      }

      //Create submission entry
      const submission = {
        type: iocType,
        value: iocValue,
        timestamp: new Date().toISOString(),
        notes: notes,
        list_name: this.listName
      };

      console.log(`[GTI-SUBMIT] Created submission entry:`, submission);

      //Add to beginning (most recent first)
      submissions.unshift(submission);

      //Enforce max entries limit (FIFO)
      if (submissions.length > this.maxEntries) {
        submissions = submissions.slice(0, this.maxEntries);
        console.log(`[GTI-SUBMIT] Trimmed to ${this.maxEntries} entries (FIFO)`);
      }

      console.log(`[GTI-SUBMIT] Saving ${submissions.length} submissions to storage...`);

      //Save back to storage
      await chrome.storage.local.set({ [this.storageKey]: submissions });

      console.log(`[GTI-SUBMIT] ✓ Successfully added ${iocType} ${iocValue} to ${this.listName} list (total: ${submissions.length})`);

      return { success: true, submission, total: submissions.length };
    } catch (error) {
      console.error('[GTI-SUBMIT] ✗ Failed to add submission:', error);
      return { success: false, error: error.message };
    }
  }

  //Remove submission by index or value
  async removeSubmission(iocValue, iocType = null) {
    try {
      const result = await chrome.storage.local.get([this.storageKey]);
      let submissions = result[this.storageKey] || [];

      //Find and remove
      const initialLength = submissions.length;
      submissions = submissions.filter(s => {
        if (iocType) {
          return !(s.value === iocValue && s.type === iocType);
        }
        return s.value !== iocValue;
      });

      const removed = initialLength - submissions.length;

      if (removed > 0) {
        await chrome.storage.local.set({ [this.storageKey]: submissions });
        console.log(`GTI Submission: Removed ${removed} entry(ies) for ${iocValue}`);
        return { success: true, removed, total: submissions.length };
      } else {
        return { success: false, error: 'Submission not found' };
      }
    } catch (error) {
      console.error('Failed to remove GTI submission:', error);
      return { success: false, error: error.message };
    }
  }

  //Get all submissions
  async getSubmissions() {
    try {
      const result = await chrome.storage.local.get([this.storageKey]);
      return result[this.storageKey] || [];
    } catch (error) {
      console.error('Failed to get GTI submissions:', error);
      return [];
    }
  }

  //Export submissions as CSV
  async exportCSV() {
    try {
      const submissions = await this.getSubmissions();

      //CSV header
      let csv = 'type,value,timestamp,notes,list_name\n';

      //CSV rows (properly escape quotes and commas)
      for (const sub of submissions) {
        const row = [
          this.escapeCSV(sub.type),
          this.escapeCSV(sub.value),
          this.escapeCSV(sub.timestamp),
          this.escapeCSV(sub.notes || ''),
          this.escapeCSV(sub.list_name || this.listName)
        ];
        csv += row.join(',') + '\n';
      }

      return csv;
    } catch (error) {
      console.error('Failed to export GTI submissions:', error);
      throw error;
    }
  }

  //Import submissions from CSV
  async importCSV(csvText) {
    try {
      //Parse CSV (simple parser - assumes well-formed CSV)
      const lines = csvText.split('\n');
      const imported = [];

      //Skip header
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        //Parse CSV row (handle quoted values)
        const values = this.parseCSVRow(line);
        if (values.length >= 3) {
          imported.push({
            type: values[0],
            value: values[1],
            timestamp: values[2],
            notes: values[3] || '',
            list_name: values[4] || this.listName
          });
        }
      }

      //Load existing and merge (dedupe by type+value)
      const result = await chrome.storage.local.get([this.storageKey]);
      let existing = result[this.storageKey] || [];

      //Merge (prefer existing timestamps)
      const merged = [...existing];
      let added = 0;

      for (const imp of imported) {
        const exists = merged.find(s => s.type === imp.type && s.value === imp.value);
        if (!exists) {
          merged.push(imp);
          added++;
        }
      }

      //Save merged list
      await chrome.storage.local.set({ [this.storageKey]: merged });

      console.log(`GTI Submission: Imported ${added} new entries (${imported.length} total in file)`);

      return { success: true, imported: added, total: merged.length };
    } catch (error) {
      console.error('Failed to import GTI submissions:', error);
      return { success: false, error: error.message };
    }
  }

  //Clear all submissions
  async clearAll() {
    try {
      await chrome.storage.local.set({ [this.storageKey]: [] });
      console.log('GTI Submission: Cleared all submissions');
      return { success: true };
    } catch (error) {
      console.error('Failed to clear GTI submissions:', error);
      return { success: false, error: error.message };
    }
  }

  //Get statistics
  async getStats() {
    try {
      const submissions = await this.getSubmissions();

      //Count by type
      const byType = {};
      for (const sub of submissions) {
        byType[sub.type] = (byType[sub.type] || 0) + 1;
      }

      return {
        total: submissions.length,
        by_type: byType,
        list_name: this.listName
      };
    } catch (error) {
      console.error('Failed to get GTI submission stats:', error);
      return { total: 0, by_type: {}, list_name: this.listName };
    }
  }

  //Escape CSV value (handle quotes and commas)
  escapeCSV(value) {
    if (value === null || value === undefined) return '';

    const str = String(value);

    //If contains comma, quote, or newline, wrap in quotes and escape existing quotes
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return '"' + str.replace(/"/g, '""') + '"';
    }

    return str;
  }

  //Parse CSV row (simple parser for quoted values)
  parseCSVRow(row) {
    const values = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < row.length; i++) {
      const char = row[i];
      const next = row[i + 1];

      if (char === '"') {
        if (inQuotes && next === '"') {
          //Escaped quote
          current += '"';
          i++; //skip next quote
        } else {
          //Toggle quotes
          inQuotes = !inQuotes;
        }
      } else if (char === ',' && !inQuotes) {
        //End of value
        values.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }

    //Add last value
    if (current || values.length > 0) {
      values.push(current.trim());
    }

    return values;
  }
}

//Export singleton
const gtiSubmissionManager = new GTISubmissionManager();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { GTISubmissionManager, gtiSubmissionManager };
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.GTISubmissionManager = GTISubmissionManager;
  self.gtiSubmissionManager = gtiSubmissionManager;
}

class SecurityEngine {
  constructor() {
    this.breachAPIs = {
      haveibeened: 'https://haveibeenpwned.com/api/v3',
      phishtank: 'https://checkurl.phishtank.com'
    };

    // Patterns that detect sensitive data across ALL websites globally
    this.sensitivePatterns = [
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card
      /\b\d{3}-?\d{2}-?\d{4}\b/,                      // SSN
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, // Email
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/,                  // IP address
      /\bpassword\s*[:=]\s*\S+/i,                      // Password field
      /\bapi[_-]?key\s*[:=]\s*\S+/i,                   // API Key
      /\b\d{10,12}\b/,                                  // Phone / account number (10-12 digits)
      /\b[A-Z]{1,2}\d{6,9}\b/,                          // Passport number pattern
      /\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b/,    // IBAN-like
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/ // Specific card patterns
    ];

    this.userSettings = {};
    this.alertQueue = [];
    this.whitelistedSites = new Set();

    // Rate-limit cookie leak alerts: track last alert time per tab to avoid spam
    this.cookieAlertCooldown = new Map(); // tabId -> lastAlertTimestamp
    this.COOKIE_ALERT_INTERVAL_MS = 60000; // max one cookie alert per tab per minute

    this.init();
  }

  async init() {
    const stored = await chrome.storage.local.get(['settings', 'whitelist', 'alerts']);
    this.userSettings = stored.settings || {
      realTimeScanning: true,
      darkWebScanning: true,
      alertLevel: 'medium',
      autoBlock: false,
      notifications: true
    };
    this.whitelistedSites = new Set(stored.whitelist || []);
    this.alertQueue = stored.alerts || [];
    await this.syncTrustedAllowRules();
    this.setupRequestListener();
    this.setupMessageListener();
    this.schedulePeriodicScans();
  }

  async syncTrustedAllowRules() {
    if (!chrome.declarativeNetRequest?.updateDynamicRules) return;

    const TRUSTED_RULE_ID_START = 10000;
    const TRUSTED_RULE_ID_END = 10999;
    const resourceTypes = [
      'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
      'object', 'xmlhttprequest', 'ping', 'csp_report', 'media',
      'websocket', 'webtransport', 'webbundle', 'other'
    ];

    try {
      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = existingRules
        .map(rule => rule.id)
        .filter(id => id >= TRUSTED_RULE_ID_START && id <= TRUSTED_RULE_ID_END);

      const trustedHosts = Array.from(this.whitelistedSites).slice(0, 900);
      const addRules = trustedHosts.map((hostname, index) => ({
        id: TRUSTED_RULE_ID_START + index,
        priority: 100,
        action: { type: 'allow' },
        condition: {
          urlFilter: '*',
          requestDomains: [hostname],
          resourceTypes
        }
      }));

      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
    } catch (e) {
      console.error('Failed to sync trusted allow rules:', e);
    }
  }

  setupRequestListener() {
    // Observe all outgoing requests across all websites
    chrome.webRequest.onBeforeRequest.addListener(
      this.analyzeRequest.bind(this),
      { urls: ['<all_urls>'] },
      ['requestBody']
    );
    chrome.webRequest.onBeforeSendHeaders.addListener(
      this.analyzeHeaders.bind(this),
      { urls: ['<all_urls>'] },
      ['requestHeaders', 'extraHeaders']
    );
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      try {
        switch (message.type) {
          case 'SCAN_DATA':
            this.scanDataForLeaks(message.data, message.url || sender.tab?.url)
              .then(result => sendResponse(result || { sensitiveData: [], reputation: {} }))
              .catch(e => sendResponse({ sensitiveData: [], reputation: {}, error: e.message }));
            return true;
          case 'CHECK_BREACH':
            this.checkDataBreach(message.email)
              .then(result => sendResponse(result || { breached: false }))
              .catch(e => sendResponse({ error: true, message: e.message }));
            return true;
          case 'UPDATE_SETTINGS':
            this.updateSettings(message.settings)
              .then(() => sendResponse({ success: true }))
              .catch(e => sendResponse({ success: false, error: e.message }));
            return true;
          case 'GET_ALERTS':
            sendResponse(this.alertQueue);
            break;
          case 'CLEAR_ALERT':
            this.clearAlert(message.alertId)
              .then(() => sendResponse({ success: true }))
              .catch(e => sendResponse({ success: false, error: e.message }));
            return true;
          case 'CLEAR_ALL_ALERTS':
            this.clearAllAlerts()
              .then(() => sendResponse({ success: true }))
              .catch(e => sendResponse({ success: false, error: e.message }));
            return true;
          case 'WHITELIST_SITE':
            this.addToWhitelist(message.url)
              .then(result => sendResponse(result || { success: true }))
              .catch(e => sendResponse({ success: false, message: e.message }));
            return true;
          case 'REMOVE_FROM_WHITELIST':
            this.removeFromWhitelist(message.url)
              .then(result => sendResponse(result || { success: true }))
              .catch(e => sendResponse({ success: false, message: e.message }));
            return true;
          case 'GET_WHITELIST':
            sendResponse(Array.from(this.whitelistedSites));
            break;
          case 'LOG_DETECTION_EVENT':
            this.logDetectionEvent(message.payload || {}, sender)
              .then(() => sendResponse({ success: true }))
              .catch(() => sendResponse({ success: false }));
            return true;
          default:
            sendResponse({ success: false, message: 'Unknown message type' });
        }
      } catch (e) {
        console.error('Message handler error:', e);
        try {
          sendResponse({ error: true, message: e.message });
        } catch (_) {
          // Response already sent or channel closed
        }
      }
    });
  }

  async logDetectionEvent(payload, sender) {
    // If real-time scanning is disabled, don't log any detection events
    if (!this.userSettings.realTimeScanning) return;

    const sourceUrl = payload.url || sender?.tab?.url || '';
    const eventType = payload.eventType || 'content_detection';
    const rawData = Array.isArray(payload.sensitiveData) ? payload.sensitiveData : [];
    const normalizedData = rawData
      .map(item => {
        if (typeof item === 'string') return { type: item };
        if (item && typeof item.type === 'string') return { type: item.type };
        return null;
      })
      .filter(Boolean);

    if (!normalizedData.length) return;

    await this.createAlert({
      type: eventType,
      severity: payload.severity || 'medium',
      url: sourceUrl,
      initiator: payload.initiator || sender?.url || null,
      data: normalizedData,
      isThirdParty: payload.isThirdParty === true,
      blocked: false,
      silent: true,
      timestamp: Date.now(),
      tabId: sender?.tab?.id
    });
  }

  async analyzeRequest(details) {
    if (!this.userSettings.realTimeScanning) return;
    try {
      const urlObj = new URL(details.url);

      if (details.requestBody) {
        const data = this.extractFormData(details.requestBody);
        if (!data.trim()) return;
        const leaks = this.detectSensitiveData(data);
        if (leaks.length) {
          const initiatorUrl = details.initiator || details.originUrl;
          const isThirdParty = this.isThirdPartyRequest(initiatorUrl, details.url);
          const destinationTrusted = this.whitelistedSites.has(urlObj.hostname);
          const initiatorTrusted = this.isWhitelistedHostFromUrl(initiatorUrl);
          const isTrustedActivity = destinationTrusted || initiatorTrusted;

          const alertType = isThirdParty ? 'third_party_data_leak' : 'data_transmission';
          const shouldBlock = isThirdParty && this.userSettings.autoBlock && !isTrustedActivity;

          let severity = 'medium';
          let silent = true;

          if (isThirdParty) {
            if (shouldBlock) {
              severity = 'critical';
              silent = false;
            } else {
              severity = 'medium';
              silent = true;
            }
          }

          await this.createAlert({
            type: alertType,
            severity,
            url: details.url,
            initiator: initiatorUrl,
            data: leaks.map(l => ({ type: l.type })),
            timestamp: Date.now(),
            tabId: details.tabId,
            blocked: shouldBlock,
            isThirdParty,
            silent
          });

          // In MV3, webRequest blocking requires 'blocking' option which is not available
          // for service workers. Return value is ignored — blocking is done via declarativeNetRequest.
        }
      }
    } catch (e) {
      console.error('Error analyzing request:', e);
    }
  }

  isThirdPartyRequest(initiatorUrl, destinationUrl) {
    try {
      if (!initiatorUrl) return false;
      const initiatorDomain = new URL(initiatorUrl).hostname;
      const destinationDomain = new URL(destinationUrl).hostname;
      return initiatorDomain !== destinationDomain;
    } catch (e) {
      return false;
    }
  }

  isWhitelistedHostFromUrl(url) {
    try {
      if (!url) return false;
      const hostname = new URL(url).hostname;
      return this.whitelistedSites.has(hostname);
    } catch (e) {
      return false;
    }
  }

  async analyzeHeaders(details) {
    // If real-time scanning is disabled, don't analyze anything
    if (!this.userSettings.realTimeScanning) return;
    
    try {
      const urlObj = new URL(details.url);
      const destinationTrusted = this.whitelistedSites.has(urlObj.hostname);
      const initiatorUrl = details.initiator || details.originUrl;
      const initiatorTrusted = this.isWhitelistedHostFromUrl(initiatorUrl);
      const isTrustedActivity = destinationTrusted || initiatorTrusted;

      const suspiciousHeaders = ['x-api-key', 'authorization', 'x-auth-token'];
      for (const header of details.requestHeaders || []) {
        const headerName = header.name.toLowerCase();

        if (headerName === 'cookie' && header.value) {
          const isThirdParty = this.isThirdPartyRequest(initiatorUrl, details.url);

          // Rate-limit cookie alerts per tab to avoid flooding the alert queue
          const tabId = details.tabId;
          const now = Date.now();
          const lastCookieAlert = this.cookieAlertCooldown.get(tabId) || 0;
          if (now - lastCookieAlert < this.COOKIE_ALERT_INTERVAL_MS) continue;
          this.cookieAlertCooldown.set(tabId, now);

          await this.createAlert({
            type: 'cookie_leak',
            severity: isThirdParty && !isTrustedActivity ? 'high' : 'medium',
            url: details.url,
            initiator: initiatorUrl,
            isThirdParty,
            blocked: false,
            data: [{ type: 'cookie' }],
            silent: !(isThirdParty && !isTrustedActivity),
            timestamp: now,
            tabId
          });

          continue;
        }

        if (suspiciousHeaders.some(h => headerName.includes(h))) {
          const leaks = this.detectSensitiveData(header.value);
          if (leaks.length) {
            await this.createAlert({
              type: 'header_leak',
              severity: 'medium',
              url: details.url,
              header: header.name,
              data: leaks.map(l => ({ type: l.type })),
              silent: true,
              timestamp: Date.now(),
              tabId: details.tabId
            });
          }
        }
      }
    } catch (e) {
      console.error('Error analyzing headers:', e);
    }
  }

  extractFormData(requestBody) {
    let data = '';
    if (requestBody.formData) {
      for (const [key, values] of Object.entries(requestBody.formData)) {
        data += `${key}: ${values.join(', ')} `;
      }
    }
    if (requestBody.raw) {
      for (const item of requestBody.raw) {
        if (item.bytes) {
          try {
            data += new TextDecoder().decode(new Uint8Array(item.bytes));
          } catch (_) {}
        }
      }
    }
    return data;
  }

  detectSensitiveData(text) {
    if (!text) return [];
    const found = [];
    const seen = new Set();
    for (const [i, pattern] of this.sensitivePatterns.entries()) {
      const matches = text.match(pattern);
      if (matches) {
        const type = this.getPatternType(i);
        if (!seen.has(type)) {
          seen.add(type);
          found.push({ type, value: matches[0], pattern: pattern.toString() });
        }
      }
    }
    return found;
  }

  getPatternType(index) {
    const types = [
      'credit_card', 'ssn', 'email', 'ip_address',
      'password', 'api_key', 'phone_or_account',
      'passport', 'iban', 'credit_card_specific'
    ];
    return types[index] || 'unknown';
  }

  async scanDataForLeaks(data, url) {
    const leaks = this.detectSensitiveData(data);
    const reputation = await this.checkUrlReputation(url);
    const recommendations = [];

    if (leaks.length) {
      recommendations.push('Sensitive data detected. Verify this site is legitimate before submitting.');
    }
    if (reputation?.malicious) {
      recommendations.push('Warning: This site is flagged as potentially malicious by Google Safe Browsing.');
    }
    if (url && !url.startsWith('https://')) {
      recommendations.push('This page does not use HTTPS. Your data may not be encrypted in transit.');
    }

    return { sensitiveData: leaks, reputation, recommendations };
  }

  async checkDataBreach(email) {
    if (!this.userSettings.darkWebScanning) return { checked: false, reason: 'Disabled' };
    try {
      // Replace YOUR_API_KEY with a real HIBP API key from haveibeenpwned.com/API/Key
      const res = await fetch(`${this.breachAPIs.haveibeened}/breachedaccount/${encodeURIComponent(email)}`, {
        method: 'GET',
        headers: { 'hibp-api-key': 'YOUR_API_KEY', 'User-Agent': 'SecureGuard' }
      });
      if (res.status === 200) {
        const data = await res.json();
        return { breached: true, breaches: data, count: data.length };
      } else if (res.status === 404) {
        return { breached: false, message: 'No breaches found' };
      } else if (res.status === 401) {
        return { error: true, message: 'Invalid HIBP API key. Replace YOUR_API_KEY in background.js.' };
      } else if (res.status === 429) {
        return { error: true, message: 'Rate limited. Please try again in a moment.' };
      }
    } catch (e) {
      console.error(e);
      return { error: true, message: 'API error' };
    }
  }

  async checkUrlReputation(url) {
    if (!url) return null;
    try {
      // Replace YOUR_GOOGLE_API_KEY with a real Google Safe Browsing API key
      const res = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_GOOGLE_API_KEY', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'secureguard', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      });
      const data = await res.json();
      return { malicious: Array.isArray(data.matches) && data.matches.length > 0, threats: data.matches || [] };
    } catch (e) {
      console.error(e);
      return { error: true };
    }
  }

  async createAlert(alert) {
    alert.id = crypto.randomUUID();

    // All alerts stored silently - no popup notifications
    alert.silent = true;

    // Store unlimited alerts — no cap on alert queue
    this.alertQueue.push(alert);
    await chrome.storage.local.set({ alerts: this.alertQueue });

    // Update badge with current alert count
    chrome.action.setBadgeText({ text: this.alertQueue.length.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
  }

  formatAlertMessage(alert) {
    try {
      const blockStatus = alert.blocked ? ' [BLOCKED]' : '';
      switch (alert.type) {
        case 'cookie_leak':
          return `Cookie transfer detected to ${new URL(alert.url).hostname}${blockStatus}`;
        case 'third_party_data_leak':
          return `Third-party data leak to ${new URL(alert.url).hostname}${blockStatus}`;
        case 'data_transmission':
          return `Sensitive data detected in form to ${new URL(alert.url).hostname}`;
        case 'header_leak':
          return `Potential header leak on ${new URL(alert.url).hostname}`;
        case 'breach_detected':
          return `Email found in ${alert.count} breaches`;
        default:
          return 'Security alert detected';
      }
    } catch (_) {
      return 'Security alert detected';
    }
  }

  async clearAlert(id) {
    this.alertQueue = this.alertQueue.filter(alert => alert.id !== id);
    await chrome.storage.local.set({ alerts: this.alertQueue });
    const count = this.alertQueue.length;
    chrome.action.setBadgeText({ text: count > 0 ? count.toString() : '' });
  }

  async clearAllAlerts() {
    this.alertQueue = [];
    await chrome.storage.local.set({ alerts: [] });
    chrome.action.setBadgeText({ text: '' });
  }

  async updateSettings(settings) {
    this.userSettings = { ...this.userSettings, ...settings };
    await chrome.storage.local.set({ settings: this.userSettings });
  }

  schedulePeriodicScans() {
    // Use chrome.alarms instead of setInterval — service workers sleep and kill setInterval
    chrome.alarms.create('periodicBreachScan', { periodInMinutes: 1440 }); // every 24 hours
    chrome.alarms.onAlarm.addListener(async (alarm) => {
      if (alarm.name !== 'periodicBreachScan') return;
      if (!this.userSettings.darkWebScanning) return;
      const { watchedEmails = [] } = await chrome.storage.local.get('watchedEmails');
      for (const email of watchedEmails) {
        const res = await this.checkDataBreach(email);
        if (res && res.breached && res.count > 0) {
          await this.createAlert({
            type: 'breach_detected',
            severity: 'critical',
            email,
            count: res.count,
            timestamp: Date.now(),
            silent: false
          });
        }
        // Space out calls to avoid rate limiting
        await new Promise(r => setTimeout(r, 1500));
      }
    });
  }

  async addToWhitelist(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      this.whitelistedSites.add(hostname);
      await chrome.storage.local.set({ whitelist: Array.from(this.whitelistedSites) });
      await this.syncTrustedAllowRules();
      return { success: true, message: `${hostname} added to whitelist` };
    } catch (e) {
      return { success: false, message: 'Invalid URL' };
    }
  }

  async removeFromWhitelist(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      this.whitelistedSites.delete(hostname);
      await chrome.storage.local.set({ whitelist: Array.from(this.whitelistedSites) });
      await this.syncTrustedAllowRules();
      return { success: true, message: `${hostname} removed from whitelist` };
    } catch (e) {
      return { success: false, message: 'Invalid URL' };
    }
  }

  isWhitelisted(hostname) {
    return this.whitelistedSites.has(hostname);
  }
}

// Initialize engine
const securityEngine = new SecurityEngine();
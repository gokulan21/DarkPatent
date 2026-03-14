class PopupController {
  constructor() {
    this.currentTab = 'dashboard';
    this.settings = {};
    this.alerts = [];
    this.stats = { sitesScanned: 0 };
    this.whitelist = [];
    this.currentTabUrl = null;
    this.currentTabHostname = null;
    this.init();
  }

  async init() {
    await this.loadData();
    this.setupEventListeners();
    this.updateUI();
    this.startPeriodicUpdate();
    this.getCurrentTabInfo();
  }

  async getCurrentTabInfo() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0] && tabs[0].url) {
        this.currentTabUrl = tabs[0].url;
        // Only parse hostname for http/https URLs — avoids crashing on chrome:// or about:blank
        if (tabs[0].url.startsWith('http://') || tabs[0].url.startsWith('https://')) {
          this.currentTabHostname = new URL(tabs[0].url).hostname;
        } else {
          this.currentTabHostname = null;
        }
      }
    } catch (e) {
      console.error('Error getting tab info:', e);
    }
  }

  async loadData() {
    try {
      const result = await chrome.storage.local.get(['settings', 'alerts', 'stats', 'whitelist']);
      this.settings = result.settings || {
        realTimeScanning: true,
        darkWebScanning: true,
        autoBlock: false,
        notifications: true,
        alertLevel: 'medium',
      };
      this.alerts = result.alerts || [];
      this.stats = result.stats || { sitesScanned: 0 };
      this.whitelist = result.whitelist || [];
    } catch (e) {
      console.error('Error loading data:', e);
    }
  }

  setupEventListeners() {
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
    });

    const scanBtn = document.getElementById('scanPageBtn');
    if (scanBtn) scanBtn.addEventListener('click', this.scanPage.bind(this));

    const clearBtn = document.getElementById('clearAlertsBtn');
    if (clearBtn) clearBtn.addEventListener('click', this.clearAlerts.bind(this));

    const exportBtn = document.getElementById('exportDataBtn');
    if (exportBtn) exportBtn.addEventListener('click', this.exportData.bind(this));

    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) settingsBtn.addEventListener('click', () => this.switchTab('settings'));

    const breachBtn = document.getElementById('breachCheckBtn');
    if (breachBtn) breachBtn.addEventListener('click', this.checkBreaches.bind(this));

    document.querySelectorAll('.toggle-switch').forEach(toggle => {
      toggle.addEventListener('click', () => {
        const setting = toggle.dataset.setting;
        const enabled = toggle.classList.toggle('active');
        this.updateSetting(setting, enabled);
      });
    });

    const alertLevelSelect = document.getElementById('alertLevel');
    if (alertLevelSelect) {
      alertLevelSelect.value = this.settings.alertLevel || 'medium';
      alertLevelSelect.addEventListener('change', e => this.updateSetting('alertLevel', e.target.value));
    }

    const resetBtn = document.getElementById('resetSettingsBtn');
    if (resetBtn) resetBtn.addEventListener('click', this.resetSettings.bind(this));

    const whitelistBtn = document.getElementById('whitelistCurrentBtn');
    if (whitelistBtn) whitelistBtn.addEventListener('click', this.whitelistCurrentSite.bind(this));
  }

  switchTab(tabName) {
    this.currentTab = tabName;
    document.querySelectorAll('.tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.toggle('active', content.id === tabName);
    });
    if (tabName === 'alerts') this.renderAlerts();
    if (tabName === 'settings') this.renderWhitelist();
  }

  updateUI() {
    const protectionStatus = document.getElementById('protectionStatus');
    if (protectionStatus) {
      protectionStatus.textContent = this.settings.realTimeScanning ? 'ACTIVE' : 'DISABLED';
      protectionStatus.style.color = this.settings.realTimeScanning ? '#4CAF50' : '#f44336';
    }

    const alertCount = document.getElementById('alertCount');
    if (alertCount) alertCount.textContent = this.alerts.length;

    const sitesScanned = document.getElementById('sitesScanned');
    if (sitesScanned) sitesScanned.textContent = this.stats.sitesScanned;

    document.querySelectorAll('.toggle-switch').forEach(toggle => {
      const setting = toggle.dataset.setting;
      if (this.settings[setting]) {
        toggle.classList.add('active');
      } else {
        toggle.classList.remove('active');
      }
    });

    const alertLevelSelect = document.getElementById('alertLevel');
    if (alertLevelSelect) alertLevelSelect.value = this.settings.alertLevel || 'medium';

    this.renderWhitelist();
  }

  renderWhitelist() {
    const container = document.getElementById('whitelistContainer');
    if (!container) return;

    if (!this.whitelist || this.whitelist.length === 0) {
      container.innerHTML = '<p style="opacity: 0.6; text-align: center; margin: 10px 0;">No whitelisted sites</p>';
      return;
    }

    container.innerHTML = '';
    this.whitelist.forEach(hostname => {
      const item = document.createElement('div');
      item.style.cssText = `
        background: rgba(0, 0, 0, 0.35);
        border: 1px solid rgba(255, 255, 255, 0.25);
        padding: 9px 10px;
        border-radius: 6px;
        margin: 4px 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 13px;
        gap: 10px;
      `;

      const nameSpan = document.createElement('span');
      nameSpan.textContent = 'https://' + hostname;
      nameSpan.style.cssText = `
        color: #ffffff;
        font-weight: 600;
        text-decoration: underline;
        text-decoration-color: rgba(255, 255, 255, 0.6);
        overflow-wrap: anywhere;
      `;

      const removeBtn = document.createElement('button');
      removeBtn.textContent = '✕';
      removeBtn.style.cssText = `
        background: rgba(244,67,54,0.75);
        border: none;
        color: white;
        padding: 3px 9px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 12px;
        font-weight: 700;
        flex-shrink: 0;
      `;
      removeBtn.addEventListener('click', () => this.removeFromWhitelistUI(hostname));

      item.appendChild(nameSpan);
      item.appendChild(removeBtn);
      container.appendChild(item);
    });
  }

  renderAlerts() {
    const container = document.getElementById('alertsList');
    if (!container) return;

    if (this.alerts.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔒</div>No alerts</div>';
      return;
    }

    container.innerHTML = '';
    // Show newest first
    const sorted = [...this.alerts].reverse();
    sorted.forEach(alert => {
      const item = document.createElement('div');
      item.className = 'alert-item';

      // Different styling for silent (logged-only) vs active alerts
      if (alert.silent) {
        item.style.cssText = `
          background: rgba(244, 180, 54, 0.4);
          margin: 8px 0;
          padding: 10px;
          border-radius: 8px;
          cursor: default;
          user-select: text;
          border-left: 4px solid #FFC107;
        `;
      }

      const strong = document.createElement('strong');
      strong.textContent = this.formatAlertType(alert.type) + ' — ' + this.formatTime(alert.timestamp);
      item.appendChild(strong);

      const msg = document.createElement('div');
      msg.style.cssText = 'font-size:13px; margin: 4px 0 8px; opacity:0.9;';
      msg.textContent = this.formatAlertMessage(alert);
      item.appendChild(msg);

      // Show detected data type badge for silent alerts
      if (alert.silent) {
        const detectedTypes = Array.isArray(alert.data)
          ? alert.data.map(d => d.type).filter(Boolean)
          : [];
        const badgeLabel = detectedTypes.length
          ? `DATA: ${detectedTypes.map(t => t.replace(/_/g, ' ').toUpperCase()).join(', ')}`
          : 'DATA ALERT';

        const badge = document.createElement('div');
        badge.style.cssText = `
          display: inline-block;
          background: rgba(255, 193, 7, 0.8);
          color: #333;
          padding: 2px 8px;
          border-radius: 3px;
          font-size: 11px;
          font-weight: 600;
          margin-right: 5px;
          margin-bottom: 4px;
        `;
        badge.textContent = badgeLabel;
        item.insertBefore(badge, msg);
      }

      const btn = document.createElement('button');
      btn.className = 'dismissBtn';
      btn.textContent = 'Dismiss';
      btn.style.cssText = 'background:rgba(255,255,255,0.25);border:none;color:white;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;';
      btn.addEventListener('click', () => this.dismissAlert(alert.id));
      item.appendChild(btn);

      container.appendChild(item);
    });
  }

  formatAlertType(type) {
    return (type || 'unknown').replace(/_/g, ' ').toUpperCase();
  }

  formatTime(ts) {
    if (!ts) return 'unknown time';
    const diff = (Date.now() - ts) / 1000;
    if (diff < 60) return `${Math.floor(diff)} seconds ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    return `${Math.floor(diff / 86400)} days ago`;
  }

  formatAlertMessage(alert) {
    try {
      const blockStatus = alert.blocked ? ' ✓ [BLOCKED]' : '';
      const detectedTypes = Array.isArray(alert.data)
        ? alert.data.map(d => d.type).filter(Boolean)
        : [];
      const formattedTypes = detectedTypes.length
        ? detectedTypes.map(t => t.replace(/_/g, ' ').toUpperCase()).join(', ')
        : null;
      switch (alert.type) {
        case 'cookie_leak':
          return `Cookie transfer detected to ${new URL(alert.url).hostname}${blockStatus}${formattedTypes ? ` | Detected: ${formattedTypes}` : ''}`;
        case 'third_party_data_leak':
          return `Third-party leak to ${new URL(alert.url).hostname}${blockStatus}${formattedTypes ? ` | Detected: ${formattedTypes}` : ''}`;
        case 'data_transmission':
          return `Sensitive data detected going to ${new URL(alert.url).hostname}${formattedTypes ? ` | Detected: ${formattedTypes}` : ''}`;
        case 'header_leak':
          return `Potential header leak on ${new URL(alert.url).hostname}${formattedTypes ? ` | Detected: ${formattedTypes}` : ''}`;
        case 'breach_detected':
          return `Email found in ${alert.count} breach(es).`;
        default:
          return (alert.message || 'Security alert detected.') + (formattedTypes ? ` | Detected: ${formattedTypes}` : '');
      }
    } catch (_) {
      return 'Security alert detected.';
    }
  }

  async dismissAlert(id) {
    this.alerts = this.alerts.filter(a => a.id !== String(id));
    await chrome.storage.local.set({ alerts: this.alerts });
    try {
      await chrome.runtime.sendMessage({ type: 'CLEAR_ALERT', alertId: id });
    } catch (e) {
      console.warn('Clear alert message failed:', e);
    }
    this.renderAlerts();
    this.updateUI();
  }

  async scanPage() {
    this.switchTab('dashboard');
    this.setScanStatus('🔄 Scanning current page...', 'progress');

    if (this.settings.realTimeScanning === false) {
      this.setScanStatus('Extension is disabled. Enable Real-Time Scanning to use it.', 'warning');
      this.scrollToScanResult();
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id || !tab.url) {
        this.setScanStatus('❌ No valid web page is active for scanning.', 'unsafe');
        this.scrollToScanResult();
        return;
      }

      // Cannot inject content script into chrome:// or extension pages
      if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
        this.setScanStatus('⚠️ Scanning works only on normal web pages (http/https).', 'warning');
        this.scrollToScanResult();
        return;
      }

      await this.incrementScannedSites();
      let response;
      try {
        response = await chrome.tabs.sendMessage(tab.id, { type: 'SCAN_PAGE' });
      } catch (messageError) {
        this.setScanStatus('⚠️ Cannot scan: content script not loaded on this page.', 'warning');
        this.scrollToScanResult();
        return;
      }

      if (!response || typeof response.safe !== 'boolean') {
        this.setScanStatus('⚠️ Scan completed, but no result was returned.', 'warning');
        this.scrollToScanResult();
        return;
      }

      if (response.safe) {
        this.setScanStatus('✅ SAFE: No significant risks were detected on this page.', 'safe');
      } else {
        const reasons = Array.isArray(response.reasons) ? response.reasons : [];

        if (reasons.includes('Extension is disabled. Enable Real-Time Scanning to use it.')) {
          this.setScanStatus('Extension is disabled. Enable Real-Time Scanning to use it.', 'warning');
          this.scrollToScanResult();
          return;
        }

        const detectedTypes = Array.isArray(response.detectedTypes) ? response.detectedTypes : [];
        const formattedTypes = detectedTypes.length
          ? ` Detected: ${detectedTypes.map(t => String(t).replace(/_/g, ' ').toUpperCase()).join(', ')}.`
          : '';
        const reasonText = reasons.length ? ` Reasons: ${reasons.join(' | ')}` : '';
        this.setScanStatus(`⚠️ NOT SAFE: Potential risks detected.${formattedTypes}${reasonText}`, 'unsafe');
      }
      this.scrollToScanResult();
    } catch (e) {
      console.error('Error sending scan message:', e);
      this.setScanStatus('❌ Failed to scan: page is not ready or content script is not reachable.', 'unsafe');
      this.scrollToScanResult();
    }
  }

  async incrementScannedSites() {
    const nextValue = Number(this.stats?.sitesScanned || 0) + 1;
    this.stats = { ...this.stats, sitesScanned: nextValue };
    await chrome.storage.local.set({ stats: this.stats });
    this.updateUI();
  }

  setScanStatus(message, tone = 'neutral') {
    const scanStatus = document.getElementById('scanStatus');
    if (!scanStatus) return;

    scanStatus.textContent = message;
    scanStatus.style.fontWeight = '600';
    scanStatus.style.fontSize = '15px';
    scanStatus.style.lineHeight = '1.6';
    scanStatus.style.minHeight = '60px';
    scanStatus.style.display = 'flex';
    scanStatus.style.alignItems = 'center';
    scanStatus.style.justifyContent = 'center';
    scanStatus.style.textAlign = 'center';
    scanStatus.style.padding = '16px';
    scanStatus.style.borderRadius = '12px';
    scanStatus.style.transition = 'all 0.3s ease';

    if (tone === 'safe') {
      scanStatus.style.color = '#ffffff';
      scanStatus.style.background = 'linear-gradient(135deg, #4CAF50 0%, #45a049 100%)';
      scanStatus.style.border = '2px solid #4CAF50';
      scanStatus.style.boxShadow = '0 0 16px rgba(76, 175, 80, 0.4)';
      return;
    }
    if (tone === 'unsafe') {
      scanStatus.style.color = '#ffffff';
      scanStatus.style.background = 'linear-gradient(135deg, #f44336 0%, #d32f2f 100%)';
      scanStatus.style.border = '2px solid #f44336';
      scanStatus.style.boxShadow = '0 0 16px rgba(244, 67, 54, 0.4)';
      return;
    }
    if (tone === 'warning') {
      scanStatus.style.color = '#ffffff';
      scanStatus.style.background = 'linear-gradient(135deg, #f57c00 0%, #e65100 100%)';
      scanStatus.style.border = '2px solid #f57c00';
      scanStatus.style.boxShadow = '0 0 16px rgba(245, 124, 0, 0.4)';
      return;
    }
    scanStatus.style.color = 'rgba(255,255,255,0.9)';
    scanStatus.style.background = 'rgba(0, 0, 0, 0.25)';
    scanStatus.style.border = 'none';
    scanStatus.style.boxShadow = 'none';
  }

  scrollToScanResult() {
    const scanStatus = document.getElementById('scanStatus');
    if (scanStatus) {
      setTimeout(() => {
        scanStatus.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 100);
    }
  }

  async clearAlerts() {
    this.alerts = [];
    this.stats = { sitesScanned: 0 };
    await chrome.storage.local.set({ alerts: [], stats: this.stats });
    try {
      await chrome.runtime.sendMessage({ type: 'CLEAR_ALL_ALERTS' });
    } catch (e) {
      console.warn('Clear all alerts message failed:', e);
    }
    this.renderAlerts();
    this.updateUI();
  }

  async exportData() {
    try {
      const data = JSON.stringify({
        exportedAt: new Date().toISOString(),
        totalAlerts: this.alerts.length,
        alerts: this.alerts.map(a => ({
          id: a.id,
          type: a.type,
          severity: a.severity,
          url: a.url || null,
          timestamp: a.timestamp,
          timestampISO: new Date(a.timestamp).toISOString(),
          dataTypes: a.data ? a.data.map(d => d.type) : []
        })),
        settings: this.settings
      }, null, 2);

      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      await chrome.downloads.download({
        url,
        filename: `secureguard_export_${Date.now()}.json`,
        saveAs: true
      });
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (e) {
      console.error('Error exporting data:', e);
    }
  }

  async checkBreaches() {
    const emailInput = document.getElementById('breachEmail');
    if (!emailInput) {
      alert('Internal error: email input not found.');
      return;
    }
    const email = emailInput.value.trim();
    if (!email || !email.includes('@')) {
      alert('Please enter a valid email address.');
      return;
    }
    const breachResult = document.getElementById('breachResult');
    if (breachResult) {
      breachResult.textContent = 'Checking...';
      breachResult.style.color = 'rgba(255,255,255,0.7)';
    }
    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_BREACH', email });
      if (!breachResult) return;
      if (response?.error) {
        breachResult.textContent = response.message || 'Error checking breach.';
        breachResult.style.color = '#f44336';
      } else if (response?.breached) {
        const names = response.breaches.map(b => b.Name || 'Unknown').join(', ');
        breachResult.textContent = `Found in ${response.count} breach(es): ${names}`;
        breachResult.style.color = '#f44336';
      } else {
        breachResult.textContent = 'No breaches found.';
        breachResult.style.color = '#4CAF50';
      }
    } catch (e) {
      alert('Error checking breach status.');
      console.error('Check breach error:', e);
    }
  }

  async updateSetting(key, value) {
    this.settings[key] = value;
    await chrome.storage.local.set({ settings: this.settings });
    try {
      await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: this.settings });
    } catch (e) {
      console.warn('Update settings message failed:', e);
    }
    this.updateUI();
  }

  async resetSettings() {
    this.settings = {
      realTimeScanning: true,
      darkWebScanning: true,
      autoBlock: false,
      notifications: true,
      alertLevel: 'medium'
    };
    await chrome.storage.local.set({ settings: this.settings });
    try {
      await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: this.settings });
    } catch (e) {
      console.warn('Reset settings message failed:', e);
    }
    this.updateUI();
  }

  async whitelistCurrentSite() {
    if (!this.currentTabUrl || !this.currentTabHostname) {
      alert('Could not determine current site. Make sure you are on an http/https page.');
      return;
    }

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'WHITELIST_SITE',
        url: this.currentTabUrl
      });

      if (result && result.success) {
        alert(`✓ ${this.currentTabHostname} has been whitelisted. No alerts will be shown for this site.`);
        await this.loadData();
        this.updateUI();
      } else if (result && result.message) {
        alert('Error: ' + result.message);
      }
    } catch (e) {
      console.error('Error whitelisting site:', e);
      alert('Could not whitelist site. Please try again.');
    }
  }

  async removeFromWhitelistUI(hostname) {
    try {
      const result = await chrome.runtime.sendMessage({
        type: 'REMOVE_FROM_WHITELIST',
        url: `https://${hostname}`
      });

      if (result.success) {
        await this.loadData();
        this.updateUI();
      }
    } catch (e) {
      console.error('Error removing from whitelist:', e);
    }
  }

  startPeriodicUpdate() {
    setInterval(async () => {
      await this.loadData();
      this.updateUI();
      if (this.currentTab === 'alerts') this.renderAlerts();
      if (this.currentTab === 'settings') this.renderWhitelist();
    }, 5000);
  }
}

let popup;

document.addEventListener('DOMContentLoaded', () => {
  popup = new PopupController();
});